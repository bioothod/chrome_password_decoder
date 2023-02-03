from typing import List, Dict, Union

import argparse
import base64
import binascii
import re
import sqlite3

from collections import namedtuple
from Crypto.Cipher import AES
from hashlib import pbkdf2_hmac

import gi
gi.require_version('Secret', '1')
from gi.repository import Secret

def unpad_pkcs5(data: bytes, block_size: int) -> bytes:
    pdata_len = len(data)
    padding_len = data[-1]
    if pdata_len < padding_len or padding_len > block_size:
        return data
    return data[:-padding_len]

def decode_and_unpack(decoder_key: bytes, password: bytes) -> str:
    iv = bytes(' ' * 16, 'ascii')
    cipher = AES.new(decoder_key, AES.MODE_CBC, iv)

    decoded_password = cipher.decrypt(password)
    decoded_password = unpad_pkcs5(decoded_password, AES.block_size)
    try:
        return decoded_password.decode('ascii')
    except UnicodeDecodeError:
        return ''

class DecoderV10:
    def __init__(self):
        salt = b'saltysalt'
        password = b'peanuts'
        num_iterations = 1

        self.decoder_key = pbkdf2_hmac('sha1', password, salt, num_iterations, 16)

    def decode(self, password: bytes) -> List[str]:
        return [decode_and_unpack(self.decoder_key, password)]

class DecoderV11:
    def __init__(self):
        salt = b'saltysalt'
        num_iterations = 1

        item_names = [
            'Chrome Safe Storage',
            'Chromium Safe Storage',
        ]

        self.secrets = []

        service = Secret.Service.get_sync(Secret.ServiceFlags.LOAD_COLLECTIONS)
        service.load_collections()
        for collection in service.get_collections():
            collection_label = collection.get_label()
            collection.load_items()
            for item in collection.get_items():
                item_label = item.get_label()
                if item_label not in item_names:
                    print(f'collection: {collection_label}, item: {item_label}')
                    continue

                item.load_secret_sync()
                item_value = item.get_secret().get_text()
                master_key = base64.b64decode(item_value)

                decoder_key = pbkdf2_hmac('sha1', master_key, salt, num_iterations, 16)
                print(f'collection: {collection_label}, item: {item_label}, secret: {item_value}, master_key: {binascii.hexlify(master_key)}, decoder_key: {binascii.hexlify(decoder_key)}')
                self.secrets.append(decoder_key)

    def decode(self, password: bytes) -> List[str]:
        decoded_passwords: List[str] = []

        for decoder_key in self.secrets:
            decoded_password = decode_and_unpack(decoder_key, password)
            if len(decoded_password) != 0:
                decoded_passwords.append(decoded_password)

        return decoded_passwords


class SchemaParser:
    def __init__(self, table_name: str, schema: str, decoders: Dict[str, Union[DecoderV10, DecoderV11]]):
        self.decoders = decoders

        match_query = re.match(f'CREATE TABLE \"?{table_name}\"?\\s*\\((.*)\\)', schema)
        if not match_query:
            raise ValueError(f'{table_name}: invalid schema {schema}')

        self.fields = []

        for schema_fields in match_query.group(1).split(', '):
            fields = schema_fields.split()
            name = fields[0]
            dtype = fields[1]

            if name == 'UNIQUE':
                break

            self.fields.append(name)

        #print(self.fields)
        self.Row = namedtuple('Row', self.fields)

    def feed_row(self, row):
        if len(row) != len(self.fields):
            return

        row = self.Row(*row)

        if len(row.password_value) == 0:
            #print(f'{row.origin_url}: {row.username_value}: password_value: {row.password_value}')
            return

        password_data = None
        for password_hash_version in self.decoders.keys():
            if row.password_value[:len(password_hash_version)] == password_hash_version.encode('ascii'):
                password_data = row.password_value[len(password_hash_version):]
                break

        if password_data is None:
            #print(f'{row.origin_url}: {row.username_value}: password_element: {row.password_element}, password_value: {row.password_value}: unsupported hash version')
            return

        decoded_passwords = self.decoders[password_hash_version].decode(password_data)

        print(f'url: {row.origin_url}, username: {row.username_value}, '
              f'version: {password_hash_version}, '
              f'password: {binascii.hexlify(password_data)} -> {decoded_passwords}')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True, type=str, help='SQLite "Login Data" file')
    FLAGS = parser.parse_args()

    decoders = {
        'v10': DecoderV10(),
        'v11': DecoderV11(),
    }

    con = sqlite3.connect(f'file:{FLAGS.input}?mode=ro', uri=True)
    cursor = con.cursor()

    get_tables_query = f'SELECT * FROM sqlite_master WHERE type="table";'
    tables = cursor.execute(get_tables_query)
    for res in tables.fetchall():
        table_name = res[1]
        schema_sql_str = res[4]
        #print(f'{table_name}: schema_sql: {schema_sql_str}')

        if table_name == 'logins':
            logins = SchemaParser(table_name, schema_sql_str, decoders)

            tt = cursor.execute(f'SELECT * from {table_name};')
            content = tt.fetchall()
            for row in content:
                logins.feed_row(row)

if __name__ == '__main__':
    main()
