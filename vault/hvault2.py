# Between python 3.7.4 and 3.7.6
import requests
from pyvault2.constants.pyvault_config import *
import json
from cryptography.fernet import Fernet, InvalidToken
from glob import glob
import os
from functools import wraps
import urllib3
from typing import List, Dict, Union, Optional
import hcl

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def insert_client_token_header(client_token: str = None) -> Dict:
    """
    Create header with client's token instead of root token.
    :param client_token:
        client_token obtained from gen_new_db_token function
    :return:
        dict
    """
    return {
        "Content-Type": "application/json",
        "X-Vault-Token": client_token
    }


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


def vault_init(shares: int = 5, threshold: int = 3, show_tokens: bool = False):
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
        """
        Not all functions return response, if there is return the response.
        Do not use the shortcut:
        if response:
            return response
        Because boolean will also match the condition, has to be specifically not None object.
        """
        if response is not None:
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
def enable_kv2_engine(mount_path: str = "kv"):
    """
    Enable a KV version 2 engine.
    This function only handles type kv.
    :param mount_path:
        The name of the mount_path of kv2 engine.
    """
    headers = insert_token_in_headers()

    # Payload to enable kv version 2 engine.
    payload = {
        "type": "kv",
        "options": {
            "version": "2"
        }
    }
    requests.post(VAULT_ADDRESS + VAULT_MNT + mount_path, headers=headers, data=json.dumps(payload), verify=False)


@vault_seal_mgmt
def disable_engine(mount_path: str = None):
    """
    Deletes the engine with the path specified.
    :param mount_path: the path which needs to delete.
    """
    headers = insert_token_in_headers()
    requests.delete(VAULT_ADDRESS + VAULT_MNT + mount_path, headers=headers, verify=False)


@vault_seal_mgmt
def create_update_kv2_secrets(mount_path: str = None, path: str = None, cas: int = 0, **kwargs):
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
        "data": kwargs
    }
    api_path = f"/v1/{mount_path}/data/{path}"
    api_request = {
        "url": VAULT_ADDRESS + api_path,
        "headers": headers,
        "data": json.dumps(payload),
        "verify": False
    }
    # Alternate way, but this method is too long hence I use **kwargs.
    # requests.post(VAULT_ADDRESS + api_path, headers=headers, data=json.dumps(payload), verify=False)
    requests.post(**api_request)


@vault_seal_mgmt
def kv2_secret_data(mount_path: str = None, path: str = None):
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
    data = json.loads(response.text)
    return data


def kv2_secret_filter(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        data_dict = fn(*args, **kwargs)
        response = kv2_secret_data(mount_path=data_dict["mount_path"], path=data_dict["path"])

        if data_dict['filter'] == "version":
            return response["data"]["metadata"]["version"]
        elif data_dict["filter"] == "data":
            return response["data"]["data"]
        elif data_dict["filter"] == "destroyed":
            return response["data"]["metadata"]["destroyed"]
        elif data_dict["filter"] == "created_time":
            return response["data"]["metadata"]["created_time"]

    return wrapper


@vault_seal_mgmt
def delete_kv2_secret_version(versions, mount_path=None, path=None):
    """
    Deletes a specific secret version.
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


@kv2_secret_filter
def get_kv2_secret(mount_path: str = None, path: str = None, find: str = None):
    return {
        "mount_path": mount_path,
        "path": path,
        "filter": find
    }


@vault_seal_mgmt
def delete_kv2_secret_path(mount_path: str = None, path: str = None):
    """
    Permanently removes a path under the mount_path, all versions and keys will be removed permanently.
    This deletes the metadata of keys and all versions data, hence unable to undelete.
    :param mount_path: The mount_path specified when you start a new engine.
    :param path: The path under the mount_path.
    """
    headers = insert_token_in_headers()
    api_path = f"/v1/{mount_path}/metadata/{path}"
    requests.delete(VAULT_ADDRESS + api_path, headers=headers, verify=False)


@vault_seal_mgmt
def is_secret_path_exists(mount_path: str = None, path: Optional[str] = None, engine_type="kv2"):
    headers = insert_token_in_headers()
    if engine_type == "kv2":
        api_path = f"/v1/{mount_path}/config"
    elif engine_type == "db":
        api_path = f"/v1/{mount_path}/config/{path}"
    response = requests.get(VAULT_ADDRESS + api_path, headers=headers, verify=False)
    if response.status_code == 404:
        return False
    else:
        return True


@vault_seal_mgmt
def enable_db_secret(mount_path: str = "database") -> Dict:
    """
    Enable database secret, this function is the same as enable_kv2_secret.
    The purpose is to get away with the need to remember the types of payload.
    When using this function, the payload will be configured, user only need to
    supply the database server name for the mount_path.
    :param mount_path:
        database servername, can be ip address or hostname.
    :return:
    """
    headers = insert_token_in_headers()
    payload = {
        "type": "database"
    }
    response = requests.post(VAULT_ADDRESS + VAULT_MNT + mount_path,
                             headers=headers,
                             data=json.dumps(payload),
                             verify=False)
    if response.status_code == 204:
        return {
            "status": "success",
            "message": f"Database secret engine name - {mount_path} has been enabled."
        }
    else:
        return {
            "status": "failed",
            "message": f"The server has returned this status code {response.status_code}"
        }


@vault_seal_mgmt
def create_db_static_role(mount_path: str = None,
                          role_name: str = None,
                          db_type: str = "mysql",
                          db_username: str = None,
                          db_name: str = None,
                          period: int = 86400) -> Dict:
    if str.lower(db_type) == "mysql":
        rotation_statements = "SET PASSWORD FOR '{{name}}'@'%' = PASSWORD('{{password}}');"
    elif str.lower(db_type) == "postgresql":
        rotation_statements = "ALTER USER {{name}} WITH PASSWORD '{{password}}';"
    else:
        # default to mariadb/mysql statement
        rotation_statements = "SET PASSWORD FOR '{{name}}'@'%' = PASSWORD('{{password}}');"
    payload = {
        "db_name": db_name,
        "rotation_statements": rotation_statements,
        "username": db_username,
        "rotation_period": period
    }
    api_uri = f"/v1/{mount_path}/static-roles/{role_name}"
    url = VAULT_ADDRESS + api_uri
    headers = insert_token_in_headers()
    response = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)
    if response.status_code == 204:
        return {
            "status": "success",
            "message": f"{role_name} is created for user {db_username} of {mount_path}/{db_name}."
        }
    else:
        return {
            "status": "failed",
            "message": f"The vault has returned status {response.status_code}."
        }


@vault_seal_mgmt
def create_db_static_creds_policy(policy_name: str = None,
                                  role_name: str = None,
                                  capabilities: Union[List[str], str] = None,
                                  mount_path: str = None) -> Dict:
    """
    Static policy creation. The policy is in Hashicorp Configuration Language (HCL).
    So when sending the json payload over, the value of "policy" has to be string.
    The capabilities has to look like this:
    In string: "\"read\""
    In list: ["\"read\"","\"update\"", "\"delete\""].
    The HCL has to be like the below example:
    path "mount_point/static-creds/acl" {
        capabilities = ["read", "update", "list", "delete"]
        }
    :param policy_name:
        User chosen policy name
    :param role_name:
        Created role name
    :param capabilities:
        Available capabilities are "read", "update", "create", "delete", "list"
    :param mount_path:
        Database mount point in Hashicorp's context
    :return:
        Dictonary
    """
    if isinstance(capabilities, list):
        role_capabilities = ",".join(capabilities)
    elif isinstance(capabilities, str):
        role_capabilities = capabilities
    policy = f"path \"{mount_path}/static-creds/{role_name}\" {{\ncapabilities = [ {role_capabilities} ]\n}}"
    payload = {
        "policy": policy
    }
    print(payload)
    api_uri = f"/v1/sys/policies/acl/{policy_name}"
    url = VAULT_ADDRESS + api_uri
    headers = insert_token_in_headers()
    response = requests.put(url, headers=headers, data=json.dumps(payload), verify=False)
    if response.status_code == 204:
        return {
            "status": "success",
            "message": f"Static credential policy {policy_name} has been successfully created."
        }
    else:
        return {
            "status": "failed",
            "message": f"The vault has returned status {response.status_code}.",
            "server_message": response.text
        }


@vault_seal_mgmt
def gen_new_db_token(policy_name: List[str] = None, verbose: bool = False) -> Union[Dict, str]:
    url = VAULT_ADDRESS + CREATE_TOKEN
    payload = {
        "policies": policy_name
    }
    headers = insert_token_in_headers()
    response = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)
    if not verbose:
        return json.loads(response.text)["auth"]["client_token"]
    else:
        return json.loads(response.text)


@vault_seal_mgmt
def get_db_credentials(mount_path: str = None,
                       role_name: str = None,
                       client_token: str = None,
                       verbose: bool = False) -> Dict:
    api_url = f"/v1/{mount_path}/static-creds/{role_name}"
    headers = insert_client_token_header(client_token=client_token)
    url = VAULT_ADDRESS + api_url
    response = requests.get(url, verify=False, headers=headers)
    response_pack = json.loads(response.text)
    if response.status_code == 200:
        if not verbose:
            return {
                "username": response_pack["data"]["username"],
                "password": response_pack["data"]["password"],
                "metadata": {
                    "ttl": response_pack["data"]["ttl"],
                    "last_vault_rotation": response_pack["data"]["last_vault_rotation"],
                    "request_id": response_pack["request_id"]
                }
            }
        else:
            return response_pack
    else:
        return {
            "status": "failed",
            "message": f"The vault returns status code {response.status_code}."
        }


@vault_seal_mgmt
def create_db_secrets(mount_path: str = None,
                      path: str = None,
                      db_type: str = "mysql",
                      allowed_roles: Union[List[str], str] = None,
                      username: str = None,
                      password: str = None,
                      db_addr: str = None,
                      max_open_conn: int = 5,
                      max_conn_lifetime: str = "5s",
                      db_port: str = "3306"):
    api_uri = f"/v1/{mount_path}/config/{path}"
    if str.lower(db_type) == "mysql":
        plugin_name = "mysql-database-plugin"
        connection_url = f"{username}:{password}@tcp({db_addr}:{db_port})/"
    elif str.lower(db_type) == "postgresql":
        plugin_name = "postgresql-database-plugin"
        connection_url = f"postgresql://{username}:{password}@{db_addr}:{db_port}/postgres?sslmode=disable"
    else:
        # unrecognized db type defaults to mysql.
        plugin_name = "mysql-database-plugin"
        connection_url = f"{username}:{password}@tcp({db_addr}:{db_port})/"
    payload = {
        "plugin_name": plugin_name,
        "allowed_roles": allowed_roles,
        "connection_url": connection_url,
        "max_open_connections": max_open_conn,
        "max_connection_lifetime": max_conn_lifetime
    }
    headers = insert_token_in_headers()
    url = VAULT_ADDRESS + api_uri
    response = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)
    if response.status_code == 200:
        return {
            "status": "success",
            "message": json.loads(response.text)
        }
    else:
        return {
            "status": "failed",
            "message": f"Server returns http status code {response.status_code}.",
            "server_message": response.text
        }
