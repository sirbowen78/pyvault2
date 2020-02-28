from pyvault2.vault.hvault2 import (enable_db_secret,
                                    create_db_static_creds_policy,
                                    create_db_static_role,
                                    get_db_credentials,
                                    gen_new_db_token,
                                    is_secret_path_exists,
                                    create_db_secrets)
from getpass import getpass
from sys import exit
from network.inventory.inv_helper import resolve_hostname, is_ipv4
from pprint import pprint


def demo():
    """
    Demonstration codes.
    The actual usage is used together with my api gateway for network operation purposes.
    :return:
    """
    servername = input("Database server hostname: ")
    # if servername can be resolved, use the ip address.
    ip = resolve_hostname(servername)

    # else prompt for ip address from user.
    if ip == servername:
        ip = input(f"IP address of {servername}: ")
        # Exit from the script if ip address entered is not valid.
        if not is_ipv4(ip):
            print("Invalid ip address! Bye!")
            exit(1)

    # databasename created with CREATE DATABASE databasename; in DB server.
    databasename = input("Database name: ")

    # Is the database engine enabled for the servername?
    if not is_secret_path_exists(mount_path=servername, path=databasename, engine_type="db"):
        print(f"{servername} does not exist in vault, enabling now...")
        # If not, enabled the database engine for servername.
        response = enable_db_secret(mount_path=servername)
        if response["status"] == "success":
            print(f"{servername} is enabled in vault.")
        elif response["status"] == "failed":
            print(f"Failed to enable database secret engine for {servername}.")
            exit(1)
        else:
            # In case there is no other response...
            print("Cannot get a response from the vault server, the creation might have failed.")
            exit(1)
    username = input(f"Username of {servername}: ")
    password = getpass(f"Password of {username} of database server {databasename}: ")
    print("*" * 10 + "Attempting to register to vault" + "*" * 10)

    """
    request to register database information
    """
    reg_request = {
        "mount_path": servername,
        "path": databasename,
        "allowed_roles": "*", # allow all roles
        "username": username,
        "password": password,
        "db_addr": ip
    }

    # Send the request for database configuration registration.
    vault_resp = create_db_secrets(**reg_request)
    if vault_resp["status"] == "success":
        print(vault_resp["message"])
    else:
        print(vault_resp["message"])
        print(vault_resp["server_message"])
        exit(1)
    print("*" * 10 + "Create static role" + "*" * 10)
    role_name = input("Your desired role name: ")
    db_type = {
        1: "mysql",
        2: "postgresql"
    }
    print(db_type)
    choice = int(input("Select the DB type 1 or 2: "))

    # information required for static-role creation.
    role_creation_req = {
        "mount_path": servername,
        "role_name": role_name,
        "db_type": db_type[choice],
        "db_username": username,
        "db_name": databasename
    }

    # call api to create static role.
    role_req_resp = create_db_static_role(**role_creation_req)
    if role_req_resp["status"] == "success":
        print(role_req_resp["message"])
    else:
        print(role_req_resp["message"])
        exit(1)
    print("*" * 10 + f"Next create policy for {role_name}" + "*" * 10)
    pol_name = input(f"What is your desired policy name for role {role_name}: ")

    # information required to create policy.
    pol_req = {
        "policy_name": pol_name,
        "role_name": role_name,
        # Use below commented if the capabilities is a list.
        # "capabilities": ["\"read\"", "\"update\"", "\"delete\""],
        "capabilities": "\"read\"",
        "mount_path": servername
    }

    # call api to create static-credential policy.
    pol_req_resp = create_db_static_creds_policy(**pol_req)
    if pol_req_resp["status"] == "success":
        print(pol_req_resp["message"])
    else:
        print(pol_req_resp["message"])
        print(pol_req_resp["server_message"])
        exit(1)

    # Get the client token only.
    client_token = gen_new_db_token(policy_name=[pol_name])

    # Get the database username and password with the client token in the request header.
    db_creds = get_db_credentials(mount_path=servername, role_name=role_name, client_token=client_token)
    pprint(db_creds)


if __name__ == "__main__":
    demo()
