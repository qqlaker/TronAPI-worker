# -*- coding: UTF-8 -*-

import sys, os, requests, json, pprint
from tronapi import Tron
from tronapi import HttpProvider
import requests
import base58, base64


CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"  # USDT

API_URL_BASE = 'https://api.trongrid.io/'

METHOD_BALANCE_OF = 'balanceOf(address)'

METHOD_TRANSFER = 'transfer(address,uint256)'

DEFAULT_FEE_LIMIT = 10000000


def create_wallet():
    account = tron.create_account
    is_valid = bool(tron.isAddress(account.address.hex))

    if is_valid:
        return [account.private_key, account.address.base58]
    else:
        return False


def send_transaction(from_private_key, from_address, to_address, amount):
    tron.private_key = from_private_key
    tron.default_address = from_address
    send = tron.trx.send_transaction(to_address, amount)
    print(send)


def get_balance(address):
    trx = None
    url = "https://apilist.tronscan.org/api/account"
    payload = {
        "address": address,
    }
    res = requests.get(url, params=payload)
    tokens = json.loads(res.text)["tokenBalances"]
    for token in tokens:
        if token["tokenAbbr"] == 'trx':
            trx = int(token["balance"])
    trx /= 1000000
    return trx


def address_to_parameter(addr):
    return "0" * 24 + base58.b58decode_check(addr)[1:].hex()


def amount_to_parameter(amount):
    return '%064x' % amount


def get_balance_usdt(address):
    url = API_URL_BASE + 'wallet/triggerconstantcontract'
    payload = {
        'owner_address': base58.b58decode_check(address).hex(),
        'contract_address': base58.b58decode_check(CONTRACT).hex(),
        'function_selector': METHOD_BALANCE_OF,
        'parameter': address_to_parameter(address),
    }
    resp = requests.post(url, json=payload)
    data = resp.json()

    if data['result'].get('result', None):
        val = data['constant_result'][0]
        return int(val, 16)
    else:
        print('error:', bytes.fromhex(data['result']['message']).decode())
        return False


def get_trc20_transaction(from_address, to, amount, memo=''):
    url = API_URL_BASE + 'wallet/triggersmartcontract'
    payload = {
        'owner_address': base58.b58decode_check(from_address).hex(),
        'contract_address': base58.b58decode_check(CONTRACT).hex(),
        'function_selector': METHOD_TRANSFER,
        'parameter': address_to_parameter(to) + amount_to_parameter(amount),
        "fee_limit": DEFAULT_FEE_LIMIT,
        'extra_data': base64.b64encode(memo.encode()).decode(),  # TODO: not supported yet
    }
    resp = requests.post(url, json=payload)
    data = resp.json()

    if data['result'].get('result', None):
        transaction = data['transaction']
        return transaction

    else:
        print('error:', bytes.fromhex(data['result']['message']).decode())
        raise RuntimeError


def sign_transaction(transaction, from_private_key):
    url = "https://api.shasta.trongrid.io/wallet/gettransactionsign"

    payload = {
        "transaction": {
            "raw_data": f"{transaction['raw_data']}",
            "raw_data_hex": f"{transaction['raw_data_hex']}"
        },
        "privateKey": f"{from_private_key}"
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    response = requests.request("POST", url, json=payload, headers=headers)
    data = response.json()

    if 'Error' in data:
        print('error:', data)
        raise RuntimeError
    return data


def broadcast_transaction(transaction):
    url = API_URL_BASE + 'wallet/broadcasttransaction'
    resp = requests.post(url, json=transaction)
    data = resp.json()
    print(data)


def send_transaction_usdt(from_private_key, from_address, to_address, amount):
    transaction = get_trc20_transaction(from_address, to_address, amount, memo="")
    transaction = sign_transaction(transaction, from_private_key)
    broadcast_transaction(transaction)


if __name__ == '__main__':
    full_node = HttpProvider('https://api.trongrid.io')
    solidity_node = HttpProvider('https://api.trongrid.io')
    event_server = HttpProvider('https://api.trongrid.io')

    tron = Tron(full_node=full_node,
                solidity_node=solidity_node,
                event_server=event_server)

    if len(sys.argv) <= 1:
        print('Arguments are empty')
        exit(0)
    files = os.listdir()
    if 'private_keys.txt' not in files:
        with open('private_keys.txt', 'w+') as f:
            pass
    if 'addresses.txt' not in files:
        with open('private_keys.txt', 'w+') as f:
            pass

    if sys.argv[1] == "-w":
        for i in range(int(sys.argv[2])):
            wallet_info = create_wallet()
            if wallet_info:
                with open('private_keys.txt', 'a+') as f:
                    f.write(f'{wallet_info[0]}\n')
                with open('addresses.txt', 'a+') as f:
                    f.write(f'{wallet_info[1]}\n')

    elif sys.argv[1] == "-s":
        private_keys__addresses = [[], []]
        with open('private_keys.txt', 'r+') as f:
            for line in f:
                pk = line.strip('\n')
                private_keys__addresses[0].append(pk)
        with open('addresses.txt', 'r+') as f:
            for line in f:
                adr = line.strip('\n')
                private_keys__addresses[1].append(adr)
        with open('mother_wallet.txt', 'r+') as f:
            line = f.readline()
            m_pk, m_adr = line.split(' ')[0].strip('\n'), line.split(' ')[1].strip('\n')

        amount = sys.argv[2]
        total_amount = (float(sys.argv[2])+1.1) * len(private_keys__addresses[0])

        if get_balance(m_adr) < total_amount:
            print('There are not enough TRX tokens in the mother wallet to activate all slave accounts')
            exit(1)

        for i in range(len(private_keys__addresses[0])):
            send_transaction(m_pk, m_adr, private_keys__addresses[1][i], amount)

    elif sys.argv[1] == "-c":
        private_keys__addresses = [[], []]
        with open('private_keys.txt', 'r+') as f:
            for line in f:
                pk = line.strip('\n')
                private_keys__addresses[0].append(pk)
        with open('addresses.txt', 'r+') as f:
            for line in f:
                adr = line.strip('\n')
                private_keys__addresses[1].append(adr)
        with open('mother_wallet.txt', 'r+') as f:
            line = f.readline()
            m_pk, m_adr = line.split(' ')[0].strip('\n'), line.split(' ')[1].strip('\n')

        for i in range(len(private_keys__addresses[0])):
            usdt = get_balance_usdt(private_keys__addresses[1][i])
            trx = get_balance(private_keys__addresses[1][i])
            subseq = [usdt, trx]
            print(f'{private_keys__addresses[1][i]} | trx: {trx}, usdt: {usdt/1000000}')
            for v in range(2):
                if subseq[v] != None:
                    if subseq[v] != 0.0:
                        if v == 0:
                            send_transaction_usdt(private_keys__addresses[0][i], private_keys__addresses[1][i], m_adr, get_balance_usdt(private_keys__addresses[1][i]))
                        if v == 1:
                            send_transaction(private_keys__addresses[0][i], private_keys__addresses[1][i], m_adr, get_balance(private_keys__addresses[1][i]))