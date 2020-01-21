# Between python 3.7.4 and 3.7.6
import requests
from pyvault2.constants.pyvault_config import *
import json
from cryptography.fernet import Fernet, InvalidToken
from glob import glob
import os
from functools import wraps


def get_cipher_key():
    """
    Get the cipher key from key file.
    :return: cipher key, which is used for cryptography.
    """
    if not os.path.exists(KEY_FILE_PATH):
        cipher_key = Fernet.generate_key()
        with open(KEY_FILE_PATH, "wb") as key_file:
            key_file.write(cipher_key)
    with open(KEY_FILE_PATH, "rb") as key_file:
        cipher_key = key_file.read()
    return cipher_key


def write_tokens(**kwargs):
    """
    Encrypts the seals and root token to individual files.
    :param kwargs: Gets the payload dictionary to initialize the vault.
    """
    if not os.path.exists(SEAL_PATH):
        os.makedirs(SEAL_PATH)

    cipher_key_data = get_cipher_key()
    cipher = Fernet(cipher_key_data)

    for i, v in enumerate(kwargs['keys']):
        with open(f"{SEAL_FILE_PATH}{i}", "wb") as seal_file:
            seal_file.write(cipher.encrypt(v.encode('utf-8')))
    with open(f"{TOKEN_FILE_PATH}", "wb") as token_file:
        token_file.write(cipher.encrypt(kwargs['root_token'].encode('utf-8')))


def read_tokens():
    """
    Read the seals and root token from encrypted files.
    then return keys and root token dictionary.
    :return: keys and root token
    """
    seals = list()
    cipher_key_data = get_cipher_key()
    cipher = Fernet(cipher_key_data)
    seal_file_list = [f for f in glob(f"{SEAL_FILE_PATH}*")]
    for seal_file in seal_file_list:
        with open(seal_file, "rb") as sf:
            encrypted_seal = sf.read()
        try:
            seals.append(cipher.decrypt(encrypted_seal).decode('utf-8'))
        except InvalidToken:
            pass
    with open(TOKEN_FILE_PATH, "rb")as tf:
        enc_root_token = tf.read()
    root_token = cipher.decrypt(enc_root_token).decode('utf-8')
    return {
        "keys": seals,
        "root_token": root_token
    }


def vault_init(shares=5, threshold=3, show_tokens=False):
    """
    Initializes the vault
    :param shares: determines the number of seals produced
    :param threshold: determines the minimum number of seals required to unseal
    :param show_tokens: display the seals and root tokens in console in plain text if option is True.
    """
    payload = {
        "secret_shares": shares,
        "secret_threshold": threshold
    }
    response = requests.put(VAULT_ADDRESS + VAULT_INIT, data=json.dumps(payload), verify=False)
    if show_tokens and response.status_code == 200:
        print(response.text)
    write_tokens(**json.loads(response.text))


def is_vault_sealed():
    """
    Check if vault is sealed or not.
    """
    response = requests.get(VAULT_ADDRESS + VAULT_SEAL_STATUS, verify=False)
    # response.text is string even if it looks like a dictionary.
    # so json.loads converts string object to dictionary object.
    # without json.loads, response.text["sealed"] will give an exception,
    # saying the index should be integer and not string.
    if json.loads(response.text)["sealed"]:
        return True
    else:
        return False


def unseal_vault():
    """
    Unseals the vault.
    """
    tokens = read_tokens()
    payloads = list()
    for key in tokens['keys']:
        payloads.append({
            "key": key
        })
    while is_vault_sealed():
        for payload in payloads:
            requests.put(VAULT_ADDRESS + VAULT_UNSEAL, data=json.dumps(payload), verify=False)


def seal_vault():
    """
    Seals the vault
    """
    headers = insert_token_in_headers()
    requests.put(VAULT_ADDRESS + VAULT_SEAL, headers=headers, verify=False)


def vault_seal_mgmt(fn):
    """
    This decorator manages vault unseal and seal actions.
    With this decorator I do not need to remind myself
    if the vault's seal status is seal or not.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if is_vault_sealed():
            unseal_vault()
        response = fn(*args, **kwargs)
        seal_vault()
        '''
        Not all functions return response, if there is return the response.
        '''
        if response:
            return response
    return wrapper


def insert_token_in_headers():
    """
    Insert the root token into the header.
    This is required to continue all api operation after vault is sealed.
    """
    tokens = read_tokens()
    return {
        "X-Vault-Token": tokens['root_token']
    }


@vault_seal_mgmt
def enable_kv2_engine(path="kv"):
    """
    Enable a KV version 2 engine.
    This function only handles type kv.
    :param backend_type: kv, pki, ssh, aws, azure, database, consul, ldap
    :param path: desired path, can be any name
    """
    headers = insert_token_in_headers()
    payload = {
        "type": "kv",
        "options": {
            "version": "2"
        }
    }
    requests.post(VAULT_ADDRESS + VAULT_MNT + path, headers=headers, data=json.dumps(payload), verify=False)


@vault_seal_mgmt
def disable_engine(path=None):
    """
    Deletes the engine with the path specified.
    :param path: the path which needs to delete.
    """
    headers = insert_token_in_headers()
    requests.delete(VAULT_ADDRESS + VAULT_MNT + path, headers=headers, verify=False)


@vault_seal_mgmt
def create_update_kv2_secrets(username=None, password=None, description=None, mount_path=None, path=None, cas=0):
    """
    :param username: username
    :param password: password
    :param description: if not specified then it is null
    :param mount_path: mount path created during enable secret engine
    :param path: the new path for storing dictionary
    :param cas: the number must match the current version of the secret else nothing will be updated.
    Example if current version 3, and i need to modify version 3,
    then cas has to be 3 then the update can be changed.
    """
    headers = insert_token_in_headers()
    payload = {
        "options": {
            "cas": cas
        },
        "data": {
            "username": username,
            "password": password,
            "description": description
        }
    }
    api_path = f"/v1/{mount_path}/data/{path}"
    api_request = {
        "url": VAULT_ADDRESS + api_path,
        "headers": headers,
        "data": json.dumps(payload),
        "verify": False
    }
    # Alternate way, but this method is too long hence I use **kwargs.
    #requests.post(VAULT_ADDRESS + api_path, headers=headers, data=json.dumps(payload), verify=False)
    requests.post(**api_request)


@vault_seal_mgmt
def get_kv2_secret_version(mount_path=None, path=None):
    """
    Get the current version of the secret
    :param mount_path: specify the mount path
    :param path: specify the path
    The api uri will be /v1/{mount_path}/data/{path}
    :return Only returns the version number.
    """
    headers = insert_token_in_headers()
    api_path = f"/v1/{mount_path}/data/{path}"
    response = requests.get(VAULT_ADDRESS + api_path, headers=headers, verify=False)
    version = json.loads(response.text)
    return version["data"]["metadata"]["version"]


@vault_seal_mgmt
def delete_kv2_secrets_permanently(versions, mount_path=None, path=None):
    """
    Deletes a secret version permanently.
    :param versions: accepts a list
    :param mount_path: the mount path you wish to delete from
    :param path: the path under mount path you wish to delete from.
    api uri will be /v1/{mount_path}/destroy/{path}
    """
    headers = insert_token_in_headers()
    api_path = f"/v1/{mount_path}/destroy/{path}"
    payload = {
        "versions": versions
    }
    requests.post(VAULT_ADDRESS + api_path, headers=headers, data=json.dumps(payload), verify=False)
