#!/usr/bin/python3

# Terrapin-attack vulnerability scanner for OpenSSH Servers.
# ONLY TESTED ON OPENSSH versions 9.1p1 and above.
# Not tested on any other implamentations of SSH!
# References:
#   https://terrapin-attack.com/
#   https://terrapin-attack.com/TerrapinAttack.pdf



import socket
import sys



# Parse list, looking for vulnerable algos
def return_vuln(element,element_2,num):
    if num == 1: 
        print(f"\"{element}\" found; Server is likely vulnerable to CVE-2023-48795,CVE 2023-46446, and CVE-2023-46445")
        exit(0)
    elif num == 2:
        print(f"\"{element}\" and \"{element_2}\" found; Server is likely vulnerable to CVE-2023-48795,CVE 2023-46446, and CVE-2023-46445")
        exit(0)
    else: 
        print("Server might be vulnerable, but no vulnerable ciphers found.")
        exit(0)



def check_counter_cbc(element,cbc_suffix):
    if cbc_suffix in element: 
        global cbc_algo_found 
        cbc_algo_found = element
        return True



def check_counter_etm(element,mac_algo_suffix):
    if mac_algo_suffix in element:
        global etm_algo_found
        etm_algo_found = element
        return True



def main():
    # Connection data
    host = str(sys.argv[1])
    port = int(sys.argv[2])

    # Vulnerable 
    chacha = "chacha20-poly1305@openssh.com"
    cbc_suffix = "-cbc"
    mac_algo_suffix = "-etm@openssh.com"

    # Create socket
    ssh = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    # Connect
    ssh.connect((host,port))

    # Recieve version of server
    print("Server Version is",ssh.recv(1024).decode())

    # Send version for sake of continuing key exchange process
    ssh.send("SSH-2.0-OpenSSH_9.1\n".encode())

    # Recieve server accepted algos; create list
    is_vulnerable = str(ssh.recv(2048)).split(',')
    ssh.close()

    for element in is_vulnerable:
        if "cbc_present" not in locals():
            if check_counter_cbc(element,cbc_suffix):
                cbc_present = check_counter_cbc(element,cbc_suffix)

        if "etm_present" not in locals():
            if check_counter_etm(element,mac_algo_suffix):
                etm_present = check_counter_etm(element,mac_algo_suffix)
        
        if "etm_present" and "cbc_present" in locals():
            if cbc_present and etm_present:
                global mac_algo_found,cbc_algo_found
                return_vuln(cbc_algo_found,etm_algo_found,2)

        if chacha in element: 
            return_vuln(element,None,1)
            break

    return_vuln(None,None,0)



main()
