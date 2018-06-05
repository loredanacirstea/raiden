# -*- coding: utf-8 -*-
from binascii import unhexlify
from gevent.event import AsyncResult
from typing import List, Union, Tuple
from raiden.utils.typing import Address, ChannelID

import structlog

from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_TOKEN_NETWORK,
    EVENT_CHANNEL_NEW,
)
from raiden.constants import (
    NETTINGCHANNEL_SETTLE_TIMEOUT_MIN,
    NETTINGCHANNEL_SETTLE_TIMEOUT_MAX,
)
from raiden.network.rpc.filters import (
    new_filter,
    Filter,
)
from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.transactions import (
    check_transaction_threw,
    estimate_and_transact,
)
from raiden.exceptions import (
    DuplicatedChannelError,
    InvalidSettleTimeout,
    SamePeerAddress,
)
from raiden.settings import (
    DEFAULT_POLL_TIMEOUT,
)
from raiden.utils import (
    address_decoder,
    address_encoder,
    isaddress,
    pex,
    privatekey_to_address,
)
from raiden.utils.typing import Address, ChannelID
from raiden.constants import NULL_ADDRESS

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class TokenNetwork:
    def __init__(
            self,
            jsonrpc_client,
            manager_address,
            poll_timeout=DEFAULT_POLL_TIMEOUT):
        # pylint: disable=too-many-arguments

        if not isaddress(manager_address):
            raise ValueError('manager_address must be a valid address')

        check_address_has_code(jsonrpc_client, manager_address, 'Channel Manager')

        proxy = jsonrpc_client.new_contract_proxy(
            CONTRACT_MANAGER.get_abi(CONTRACT_TOKEN_NETWORK),
            address_encoder(manager_address),
        )

        CONTRACT_MANAGER.check_contract_version(
            proxy.call('contract_version').decode(),
            CONTRACT_TOKEN_NETWORK
        )

        self.address = manager_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.poll_timeout = poll_timeout
        self.open_channel_transactions = dict()

    def _call_and_check_result(self, function_name: str, *args):
        call_result = self.proxy.call(function_name, *args)

        if call_result == b'':
            self._check_exists()
            raise RuntimeError(
                "Call to '{}' returned nothing".format(function_name)
            )
        # TODO: chek if data[0] is ChannelID?

        return call_result

    def token_address(self) -> Address:
        """ Return the token of this manager. """
        return address_decoder(self.proxy.call('token'))

    def new_netting_channel(self, other_peer: ChannelID, settle_timeout: int) -> ChannelID:
        """ Creates a new channel in the TokenNetwork contract.

        Args:
            other_peer: The peer to open the channel with.
            settle_timeout: The settle timout to use for this channel.

        Returns:
            The address of the new netting channel.
        """
        if not isaddress(other_peer):
            raise ValueError('The other_peer must be a valid address')

        invalid_timeout = (
            settle_timeout < NETTINGCHANNEL_SETTLE_TIMEOUT_MIN or
            settle_timeout > NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
        )
        if invalid_timeout:
            raise InvalidSettleTimeout('settle_timeout must be in range [{}, {}]'.format(
                NETTINGCHANNEL_SETTLE_TIMEOUT_MIN, NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
            ))

        if self.client.sender == other_peer:
            raise SamePeerAddress('The other peer must not have the same address as the client.')

        # Prevent concurrent attempts to open a channel with the same token and
        # partner address.
        if other_peer not in self.open_channel_transactions:
            new_open_channel_transaction = AsyncResult()
            self.open_channel_transactions[other_peer] = new_open_channel_transaction

            try:
                transaction_hash = self._new_netting_channel(other_peer, settle_timeout)
            except Exception as e:
                new_open_channel_transaction.set_exception(e)
                raise
            else:
                new_open_channel_transaction.set(transaction_hash)
            finally:
                self.open_channel_transactions.pop(other_peer, None)
        else:
            # All other concurrent threads should block on the result of opening this channel
            transaction_hash = self.open_channel_transactions[other_peer].get()

        netting_channel_results_encoded = self.proxy.call(
            'getChannelInfo',
            self.client.sender,
            other_peer,
        )

        # address is at index 0
        netting_channel_identifier = netting_channel_results_encoded[0]

        log.debug('netting_channel_identifier {}'.format(netting_channel_identifier))

        if not netting_channel_identifier:
            log.error(
                'netting_channel_identifier failed',
                peer1=pex(self.client.sender),
                peer2=pex(other_peer)
            )
            raise RuntimeError('netting_channel_identifier failed')

        #netting_channel_address_bin = address_decoder(netting_channel_address_encoded)

        log.info(
            'new_netting_channel called',
            peer1=pex(self.client.sender),
            peer2=pex(other_peer),
            netting_channel=netting_channel_identifier,
        )

        return netting_channel_identifier

    def _new_netting_channel(self, other_peer, settle_timeout):
        if self.channel_exists(other_peer):
            raise DuplicatedChannelError('Channel with given partner address already exists')

        transaction_hash = estimate_and_transact(
            self.proxy,
            'openChannel',
            self.client.sender,
            other_peer,
            settle_timeout,
        )

        if not transaction_hash:
            raise RuntimeError('open channel transaction failed')

        self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)

        if check_transaction_threw(self.client, transaction_hash):
            raise DuplicatedChannelError('Duplicated channel')

        return transaction_hash

    def channels_addresses(self) -> List[Tuple[Address, Address]]:
        # for simplicity the smart contract return a shallow list where every
        # second item forms a tuple
        channel_flat_encoded = self.proxy.call(
            'getChannelsParticipants',
        )

        channel_flat = [
            address_decoder(channel)
            for channel in channel_flat_encoded
        ]

        # [a,b,c,d] -> [(a,b),(c,d)]
        channel_iter = iter(channel_flat)
        return list(zip(channel_iter, channel_iter))

    def channels_by_participant(self, participant_address: Address) -> List[Address]:
        """ Return a list of channel address that `participant_address` is a participant. """
        address_list = self.proxy.call(
            'nettingContractsByAddress',
            participant_address,
        )

        return [
            address_decoder(address)
            for address in address_list
        ]

    def channel_exists(self, participant_address: Address) -> bool:
        existing_channel = self.proxy.call(
            'getChannelInfo',
            self.client.sender,
            participant_address,
        )
        existing_channel = existing_channel[2]

        log.debug('existing_channel {}'.format(existing_channel))

        return existing_channel > 0

    def _detail_participant(self, participant: Address, partner: Address):
        """ """"
        data = self._call_and_check_result('getChannelParticipantInfo', participant, partner)
        return data

    def _detail_participant_locked(self, participant: Address, partner: Address):
        data = self._call_and_check_result('getParticipantLockedAmount', participant, partner)
        return data

    def detail_channel(self, partner: Address):
        """ """"
        data = self._call_and_check_result('getChannelInfo', self.client.sender, partner)
        return data

    def detail_participants(self, partner: Address):
        our_data = self._detail_participant(self.client.sender, partner)
        partner_data = self._detail_participant(partner, self.client.sender)
        return {
            'our_address': self.client.sender,
            'our_balance': our_data[0],
            'our_withdrawn': our_data[1],
            'our_is_closer': our_data[2],
            'our_balance_hash': our_data[3],
            'our_nonce': our_data[4],
            'partner_address': partner,
            'partner_balance': partner_data[0],
            'partner_withdrawn': partner_data[1],
            'partner_is_closer': partner_data[2],
            'partner_balance_hash': partner_data[3],
            'partner_nonce': partner_data[4],
        }

    def detail_participants_locked(self, partner: Address):
        our_data = self._detail_participant_locked(self.client.sender, partner)
        partner_data = self._detail_participant_locked(partner, self.client.sender)
        return {
            'our_locked_amount': our_data,
            'partner_locked_amount': partner_data,
        }

    def detail(self, partner: Address):
        """ Returns a dictionary with the details of the netting channel.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        channel_data = self.detail_channel(partner)
        participants_data = self.detail_participants(partner)
        participants_locked_data = self.detail_participants_locked(partner)

        if channel_data[2] == 0:
            raise ValueError('Channel ({}, {}) does not exist or was settled.'.format(
                pex(self.client),
                pex(partner),
            ))

        return {
            'channel_identifier': channel_data[0],
            # TODO: rename settle_block_number ?
            'settle_timeout': channel_data[1],
            'state': channel_data[2],
            **participants_data,
            **participants_locked_data,
        }

    def settle_timeout(self, partner: Address):
        """ Returns the netting channel settle_timeout.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        channel_data = self.detail_channel(partner)
        return channel_data.get('settle_timeout')

    def opened(self):
        """ Returns the block in which the channel was created.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        return self._call_and_check_result('opened')

    def closed(self):
        """ Returns the block in which the channel was closed or 0.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        return self._call_and_check_result('closed')

    def closing_address(self):
        """ Returns the address of the closer, if the channel is closed, None
        otherwise.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        closer = self.proxy.call('closingAddress')

        if closer:
            return address_decoder(closer)

        return None

    def can_transfer(self):
        """ Returns True if the channel is opened and the node has deposit in
        it.

        Note: Having a deposit does not imply having a balance for off-chain
        transfers.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
        """
        closed = self.closed()

        if closed != 0:
            return False

        return self.detail()['our_balance'] > 0

    def deposit(self, amount):
        """ Deposit amount token in the channel.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
            ChannelBusyError: If the channel is busy with another operation
            RuntimeError: If the netting channel token address is empty.
        """
        if not isinstance(amount, int):
            raise ValueError('amount needs to be an integral number.')

        token_address = self.token_address()

        token = Token(
            self.client,
            token_address,
            self.poll_timeout,
        )
        current_balance = token.balance_of(self.node_address)

        if current_balance < amount:
            raise ValueError('deposit [{}] cant be larger than the available balance [{}].'.format(
                amount,
                current_balance,
            ))

        log.info(
            'deposit called',
            node=pex(self.node_address),
            contract=pex(self.address),
            amount=amount,
        )

        if not self.channel_operations_lock.acquire(blocking=False):
            raise ChannelBusyError(
                f'Channel with address {self.address} is '
                f'busy with another ongoing operation.'
            )

        with releasing(self.channel_operations_lock):
            transaction_hash = estimate_and_transact(
                self.proxy,
                'deposit',
                amount,
            )

            self.client.poll(
                unhexlify(transaction_hash),
                timeout=self.poll_timeout,
            )

            receipt_or_none = check_transaction_threw(self.client, transaction_hash)
            if receipt_or_none:
                log.critical(
                    'deposit failed',
                    node=pex(self.node_address),
                    contract=pex(self.address),
                )

                self._check_exists()
                raise TransactionThrew('Deposit', receipt_or_none)

            log.info(
                'deposit successful',
                node=pex(self.node_address),
                contract=pex(self.address),
                amount=amount,
            )

    def close(self, nonce, transferred_amount, locksroot, extra_hash, signature):
        """ Close the channel using the provided balance proof.

        Raises:
            AddressWithoutCode: If the channel was settled prior to the call.
            ChannelBusyError: If the channel is busy with another operation.
        """

        log.info(
            'close called',
            node=pex(self.node_address),
            contract=pex(self.address),
            nonce=nonce,
            transferred_amount=transferred_amount,
            locksroot=encode_hex(locksroot),
            extra_hash=encode_hex(extra_hash),
            signature=encode_hex(signature),
        )

        if not self.channel_operations_lock.acquire(blocking=False):
            raise ChannelBusyError(
                f'Channel with address {self.address} is '
                f'busy with another ongoing operation.'
            )

        with releasing(self.channel_operations_lock):
            transaction_hash = estimate_and_transact(
                self.proxy,
                'close',
                nonce,
                transferred_amount,
                locksroot,
                extra_hash,
                signature,
            )
            self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)

            receipt_or_none = check_transaction_threw(self.client, transaction_hash)
            if receipt_or_none:
                log.critical(
                    'close failed',
                    node=pex(self.node_address),
                    contract=pex(self.address),
                    nonce=nonce,
                    transferred_amount=transferred_amount,
                    locksroot=encode_hex(locksroot),
                    extra_hash=encode_hex(extra_hash),
                    signature=encode_hex(signature),
                )
                self._check_exists()
                raise TransactionThrew('Close', receipt_or_none)

            log.info(
                'close successful',
                node=pex(self.node_address),
                contract=pex(self.address),
                nonce=nonce,
                transferred_amount=transferred_amount,
                locksroot=encode_hex(locksroot),
                extra_hash=encode_hex(extra_hash),
                signature=encode_hex(signature),
            )

    def update_transfer(self, nonce, transferred_amount, locksroot, extra_hash, signature):
        if signature:
            log.info(
                'updateTransfer called',
                node=pex(self.node_address),
                contract=pex(self.address),
                nonce=nonce,
                transferred_amount=transferred_amount,
                locksroot=encode_hex(locksroot),
                extra_hash=encode_hex(extra_hash),
                signature=encode_hex(signature),
            )

            transaction_hash = estimate_and_transact(
                self.proxy,
                'updateTransfer',
                nonce,
                transferred_amount,
                locksroot,
                extra_hash,
                signature,
            )

            self.client.poll(
                unhexlify(transaction_hash),
                timeout=self.poll_timeout,
            )

            receipt_or_none = check_transaction_threw(self.client, transaction_hash)
            if receipt_or_none:
                log.critical(
                    'updateTransfer failed',
                    node=pex(self.node_address),
                    contract=pex(self.address),
                    nonce=nonce,
                    transferred_amount=transferred_amount,
                    locksroot=encode_hex(locksroot),
                    extra_hash=encode_hex(extra_hash),
                    signature=encode_hex(signature),
                )
                self._check_exists()
                raise TransactionThrew('Update Transfer', receipt_or_none)

            log.info(
                'updateTransfer successful',
                node=pex(self.node_address),
                contract=pex(self.address),
                nonce=nonce,
                transferred_amount=transferred_amount,
                locksroot=encode_hex(locksroot),
                extra_hash=encode_hex(extra_hash),
                signature=encode_hex(signature),
            )

    def withdraw(self, unlock_proof):
        log.info(
            'withdraw called',
            node=pex(self.node_address),
            contract=pex(self.address),
        )

        if isinstance(unlock_proof.lock_encoded, messages.Lock):
            raise ValueError('unlock must be called with a lock encoded `.as_bytes`')

        merkleproof_encoded = b''.join(unlock_proof.merkle_proof)

        transaction_hash = estimate_and_transact(
            self.proxy,
            'withdraw',
            unlock_proof.lock_encoded,
            merkleproof_encoded,
            unlock_proof.secret,
        )

        self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)

        if receipt_or_none:
            log.critical(
                'withdraw failed',
                node=pex(self.node_address),
                contract=pex(self.address),
                lock=unlock_proof,
            )
            self._check_exists()
            raise TransactionThrew('Withdraw', receipt_or_none)

        log.info(
            'withdraw successful',
            node=pex(self.node_address),
            contract=pex(self.address),
            lock=unlock_proof,
        )

    def settle(self):
        """ Settle the channel.

        Raises:
            ChannelBusyError: If the channel is busy with another operation
        """
        log.info(
            'settle called',
            node=pex(self.node_address),
        )

        if not self.channel_operations_lock.acquire(blocking=False):
            raise ChannelBusyError(
                f'Channel with address {self.address} is '
                f'busy with another ongoing operation'
            )

        with releasing(self.channel_operations_lock):
            transaction_hash = estimate_and_transact(
                self.proxy,
                'settle',
            )

            self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)
            receipt_or_none = check_transaction_threw(self.client, transaction_hash)
            if receipt_or_none:
                log.info(
                    'settle failed',
                    node=pex(self.node_address),
                    contract=pex(self.address),
                )
                self._check_exists()
                raise TransactionThrew('Settle', receipt_or_none)

            log.info(
                'settle successful',
                node=pex(self.node_address),
                contract=pex(self.address),
            )

    def channelnew_filter(
            self,
            from_block: Union[str, int] = 0,
            to_block: Union[str, int] = 'latest') -> Filter:
        """ Install a new filter for ChannelNew events.

        Args:
            start_block:Create filter starting from this block number (default: 0).
            end_block: Create filter stopping at this block number (default: 'latest').

        Return:
            The filter instance.
        """
        topics = [CONTRACT_MANAGER.get_event_id(EVENT_CHANNEL_NEW)]

        channel_manager_address_bin = self.proxy.contract_address
        filter_id_raw = new_filter(
            self.client,
            channel_manager_address_bin,
            topics,
            from_block=from_block,
            to_block=to_block
        )

        return Filter(
            self.client,
            filter_id_raw,
        )

    def events_filter(
            self,
            topics: Optional[List],
            from_block: Optional[int] = None,
            to_block: Optional[int] = None) -> Filter:
        """ Install a new filter for an array of topics emitted by the netting contract.
        Args:
            topics: A list of event ids to filter for. Can also be None,
                    in which case all events are queried.
            from_block: The block number at which to start looking for events.
            to_block: The block number at which to stop looking for events.
        Return:
            Filter: The filter instance.
        """
        netting_channel_address_bin = self.proxy.contract_address
        filter_id_raw = new_filter(
            self.client,
            netting_channel_address_bin,
            topics=topics,
            from_block=from_block,
            to_block=to_block
        )

        return Filter(
            self.client,
            filter_id_raw,
        )

    def all_events_filter(self, from_block=None, to_block=None):
        """ Install a new filter for all the events emitted by the current netting channel contract

        Return:
            Filter: The filter instance.
        """
        return self.events_filter(None, from_block, to_block)
