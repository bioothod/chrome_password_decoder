from typing import List, Dict, Union

import argparse
import re
import sqlite3

from collections import namedtuple
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES

def unpad_pkcs5(data: bytes, block_size: int) -> bytes:
    pdata_len = len(data)
    padding_len = data[-1]
    if pdata_len < padding_len or padding_len > block_size:
        return data
    return data[:-padding_len]

class DecoderV10:
    def __init__(self):
        salt = b'saltysalt'
        password = b'peanuts'
        num_iterations = 1

        self.decoder_key = pbkdf2_hmac('sha1', password, salt, num_iterations, 16)

    def decode(self, password: bytes) -> bytes:
        iv = bytes(' ' * 16, 'ascii')
        cipher = AES.new(self.decoder_key, AES.MODE_CBC, iv)

        decoded_password = cipher.decrypt(password)
        decoded_password = unpad_pkcs5(decoded_password, AES.block_size)
        return decoded_password

class DecoderV11:
    def __init__(self):
        salt = b'saltysalt'
        password = b'peanuts'
        num_iterations = 1

        decoder_key = pbkdf2_hmac('sha1', password, salt, num_iterations, 16)

    def decode(self, password: bytes) -> bytes:
        iv = bytes(' ' * 16, 'ascii')
        cipher = AES.new(self.decoder_key, AES.MODE_CBC, iv)

        decoded_password = cipher.decrypt(password)
        decoded_password = unpad_pkcs5(decoded_password, AES.block_size)
        return decoded_password


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

        print(self.fields)
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

        if 'gov.uk' in row.origin_url:
            decoded_password = self.decoders[password_hash_version].decode(password_data)

            print(f'{row.origin_url}: {row.username_value}: '
                  f'version: {password_hash_version}, '
                  f'password_len: {len(password_data)}, '
                  f'password: {password_data} -> {decoded_password}')

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
