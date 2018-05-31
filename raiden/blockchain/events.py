# -*- coding: utf-8 -*-
import itertools
from collections import namedtuple, defaultdict

import structlog

from raiden.blockchain.abi import *
from raiden.exceptions import (
    AddressWithoutCode,
    EthNodeCommunicationError,
)
from raiden.network.rpc.filters import get_filter_events
from raiden.utils import address_decoder, pex
from raiden.network.rpc.smartcontract_proxy import decode_event

EventListener = namedtuple(
    'EventListener',
    ('event_name', 'filter', 'abi', 'filter_creation_function'),
)
Proxies = namedtuple(
    'Proxies',
    ('registry', 'token_networks'),
)

# `new_filter` uses None to signal the absence of topics filters
ALL_EVENTS = None
log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def poll_event_listener(eth_filter, abi):
    result = list()

    for log_event in eth_filter.changes():
        decoded_event = dict(decode_event(
            abi,
            log_event['event_data']
        ))

        if decoded_event is not None:
            decoded_event['block_number'] = log_event.get('block_number')
            event = Event(
                log_event['address'],
                decoded_event,
            )
            result.append(event)

    return result


def get_contract_events(
        chain,
        abi,
        contract_address,
        topics,
        from_block,
        to_block):
    """ Query the blockchain for all events of the smart contract at
    `contract_address` that match the filters `topics`, `from_block`, and
    `to_block`.
    """
    # Note: Issue #452 (https://github.com/raiden-network/raiden/issues/452)
    # tracks a suggested TODO, which will reduce the 3 RPC calls here to only
    # one using `eth_getLogs`. It will require changes in all testing frameworks
    # to be implemented though.

    events = get_filter_events(
        chain.client,
        contract_address,
        topics=topics,
        from_block=from_block,
        to_block=to_block
    )

    result = []
    for event in events:
        decoded_event = dict(decode_event(abi, event['event_data']))
        if event.get('block_number'):
            decoded_event['block_number'] = event['block_number']
        result.append(decoded_event)
    return result


# These helpers have a better descriptive name and provide the translator for
# the caller.

def get_all_token_network_events(
        chain,
        token_network_address,
        events=ALL_EVENTS,
        from_block=0,
        to_block='latest'):
    """ Helper to get all events of the TokenNetwork at
    `token_address`.
    """

    return get_contract_events(
        chain,
        CONTRACT_MANAGER.get_abi(CONTRACT_TOKEN_NETWORK),
        token_network_address,
        events,
        from_block,
        to_block,
    )


def get_all_token_network_registry_events(
        chain,
        token_network_registry_address,
        events=ALL_EVENTS,
        from_block=0,
        to_block='latest'):
    """ Helper to get all events of the Registry contract at
    `registry_address`.
    """
    return get_contract_events(
        chain,
        CONTRACT_MANAGER.get_abi(CONTRACT_TOKEN_NETWORK_REGISTRY),
        token_network_registry_address,
        events,
        from_block,
        to_block,
    )


def get_relevant_proxies(chain, node_address, registry_address):
    token_network_registry = chain.registry(registry_address)

    token_networks = list()

    for token_network_address in token_network_registry.manager_addresses():
        channel_manager = token_network_registry.manager(token_network_address)
        token_networks.append(channel_manager)

    proxies = Proxies(
        token_network_registry,
        token_networks,
    )

    return proxies


def decode_event_to_internal(event):
    """ Enforce the binary encoding of address for internal usage. """
    data = event.event_data

    # Note: All addresses inside the event_data must be decoded.
    if data['event'] == EVENT_TOKEN_ADDED:
        data['token_network_address'] = address_decoder(data['args']['token_network_address'])
        data['token_address'] = address_decoder(data['args']['token_address'])

    elif data['event'] == EVENT_CHANNEL_NEW:
        data['channel_identifier'] = address_decoder(data['args']['channel_identifier'])
        data['participant1'] = address_decoder(data['args']['participant1'])
        data['participant2'] = address_decoder(data['args']['participant2'])
        data['settle_timeout'] = address_decoder(data['args']['settle_timeout'])

    elif data['event'] == EVENT_CHANNEL_NEW_BALANCE:
        data['channel_identifier'] = address_decoder(data['args']['channel_identifier'])
        data['participant'] = address_decoder(data['args']['participant'])
        data['deposit'] = address_decoder(data['args']['deposit'])

    elif data['event'] == EVENT_CHANNEL_WITHDRAW:
        data['channel_identifier'] = address_decoder(data['args']['channel_identifier'])
        data['participant'] = address_decoder(data['args']['participant'])
        data['withdrawn_amount'] = address_decoder(data['args']['withdrawn_amount'])

    elif data['event'] == EVENT_CHANNEL_UNLOCK:
        data['channel_identifier'] = address_decoder(data['args']['channel_identifier'])
        data['participant'] = address_decoder(data['args']['participant'])
        data['unlocked_amount'] = address_decoder(data['args']['unlocked_amount'])
        data['returned_tokens'] = address_decoder(data['args']['returned_tokens'])

    elif data['event'] == EVENT_TRANSFER_UPDATED:
        data['channel_identifier'] = address_decoder(data['args']['channel_identifier'])
        data['closing_participant'] = address_decoder(data['args']['closing_participant'])

    elif data['event'] == EVENT_CHANNEL_CLOSED:
        data['channel_identifier'] = address_decoder(data['args']['channel_identifier'])
        data['closing_participant'] = address_decoder(data['args']['closing_participant'])

    elif data['event'] == EVENT_CHANNEL_SETTLED:
        data['channel_identifier'] = address_decoder(data['args']['channel_identifier'])

    elif data['event'] == EVENT_CHANNEL_SECRET_REVEALED:
        data['secrethash'] = address_decoder(data['secrethash'])

    return event


class Event:
    def __init__(self, originating_contract, event_data):
        self.originating_contract = originating_contract
        self.event_data = event_data

    def __repr__(self):
        return '<Event contract: {} event: {}>'.format(
            pex(self.originating_contract),
            self.event_data,
        )


class BlockchainEvents:
    """ Events polling. """

    def __init__(self):
        self.event_listeners = list()

    def poll_all_event_listeners(self, from_block=None):
        result = list()
        reinstalled_filters = False

        while True:
            try:
                for event_listener in self.event_listeners:
                    decoded_events = poll_event_listener(
                        event_listener.filter,
                        event_listener.abi,
                    )
                    result.extend(decoded_events)
                break
            except EthNodeCommunicationError as e:
                # If the eth client has restarted and we reconnected to it then
                # filters will no longer exist there. In that case we will need
                # to recreate all the filters.
                if not reinstalled_filters and str(e) == 'filter not found':
                    log.debug('reinstalling eth filters')

                    result = list()
                    reinstalled_filters = True
                    updated_event_listerners = list()

                    for event_listener in self.event_listeners:
                        new_listener = EventListener(
                            event_listener.event_name,
                            event_listener.filter_creation_function(from_block=from_block),
                            event_listener.abi,
                            event_listener.filter_creation_function,
                        )
                        updated_event_listerners.append(new_listener)

                    self.event_listeners = updated_event_listerners
                else:
                    raise e

        return result

    def poll_blockchain_events(self, from_block=None):
        for event in self.poll_all_event_listeners(from_block):
            yield decode_event_to_internal(event)

    def uninstall_all_event_listeners(self):
        for listener in self.event_listeners:
            listener.filter.uninstall()

        self.event_listeners = list()

    def add_event_listener(self, event_name, eth_filter, abi, filter_creation_function):
        event = EventListener(
            event_name,
            eth_filter,
            abi,
            filter_creation_function,
        )
        self.event_listeners.append(event)

        return poll_event_listener(eth_filter, abi)

    def add_registry_listener(self, registry_proxy, from_block=None):
        tokenadded = registry_proxy.tokenadded_filter(from_block)
        registry_address = registry_proxy.address

        self.add_event_listener(
            '{0} {1}'.format(CONTRACT_TOKEN_NETWORK_REGISTRY_NAME, pex(registry_address)),
            tokenadded,
            CONTRACT_MANAGER.get_abi(CONTRACT_TOKEN_NETWORK_REGISTRY),
            registry_proxy.tokenadded_filter,
        )

    def add_channel_manager_listener(self, channel_manager_proxy, from_block=None):
        channelnew = channel_manager_proxy.channelnew_filter(from_block)
        manager_address = channel_manager_proxy.address

        self.add_event_listener(
            '{0} {1}'.format(CONTRACT_TOKEN_NETWORK_NAME, pex(manager_address)),
            channelnew,
            CONTRACT_MANAGER.get_abi(CONTRACT_TOKEN_NETWORK),
            channel_manager_proxy.channelnew_filter,
        )

    def add_proxies_listeners(self, proxies, from_block=None):
        self.add_registry_listener(proxies.registry, from_block)

        for manager in proxies.token_networks:
            self.add_channel_manager_listener(manager, from_block)
