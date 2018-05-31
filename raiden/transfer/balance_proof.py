# -*- coding: utf-8 -*-
from raiden.utils import sha3
from raiden.encoding.messages import (
    nonce as nonce_field,
    transferred_amount as transferred_amount_field,
    locked_amount as locked_amount_field
)


def signing_data(
        nonce: int,
        transferred_amount: int,
        locked_amount: bytes,
        channel_address: bytes,
        locksroot: bytes,
        extra_hash: bytes,
) -> bytes:

    nonce_bytes = nonce_field.encoder.encode(nonce, nonce_field.size_bytes)
    pad_size = nonce_field.size_bytes - len(nonce_bytes)
    nonce_bytes_padded = nonce_bytes.rjust(pad_size, b'\x00')

    transferred_amount_bytes = transferred_amount_field.encoder.encode(
        transferred_amount,
        transferred_amount_field.size_bytes,
    )
    transferred_amount_bytes_padded = transferred_amount_bytes.rjust(pad_size, b'\x00')

    locked_amount_bytes = locked_amount_field.encoder.encode(
        locked_amount,
        locked_amount_field.size_bytes,
    )
    locked_amount_bytes_padded = locked_amount_bytes.rjust(pad_size, b'\x00')

    data_that_was_signed = (
        nonce_bytes_padded +
        sha3(transferred_amount_bytes_padded + locked_amount_bytes_padded + locksroot) +
        channel_address +
        extra_hash
    )

    return data_that_was_signed


def pack_signing_data(
        nonce: bytes,
        transferred_amount: bytes,
        locked_amount: bytes,
        channel_address: bytes,
        locksroot: bytes,
        extra_hash: bytes,
) -> bytes:

    data_that_was_signed = (
        nonce +
        sha3(transferred_amount + locked_amount + locksroot) +
        channel_address +
        extra_hash
    )

    return data_that_was_signed
