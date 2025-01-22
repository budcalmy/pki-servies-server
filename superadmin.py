import requests
import pty

def init_system_interactive():
    username = input("Введите логин суперадмина: ") or "superadmin" #todo
    password = input("Введите пароль суперадмина: ") or "12345" #todo

    url = "http://0.0.0.0:5050/init"
    data = {
        "username": username,
        "password": password,
    }
    response = requests.post(url, json=data)
    
    if response.status_code != 200:
        print("Ошибка авторизации пользователя:", response.json().get("detail", "Unknown error"))
        return
    
    response_data = response.json()
    if response_data.get("status") != "success":
        print("Error:", response_data.get("message", "Unknown error"))
        return
    
    print(response_data['message'])
    
    key_length = input("Enter key length (default 4096): ") or 4096
    root_key_name = input("Enter root key name (default root.key.pem): ") or "root.key.pem"
    issuer_key_name = input("Enter issuer key name (default issuer.key.pem): ") or "issuer.key.pem"
    root_cert_name = input("Enter root certificate name (default root.cert.pem): ") or "root.cert.pem"
    db_password = input("Enter database password: ") or "12345" #todo
    crl_name = input("Enter CRL file name (default issuer.crl.pem): ") or "issuer.crl.pem"
    
    args = [
        "--key-length", str(key_length),
        "--root-key", root_key_name,
        "--issuer-key", issuer_key_name,
        "--root-cert", root_cert_name,
        "--db-password", db_password,
        "--crl-name", crl_name
    ]
    
    cpp_program = response_data["cpp_program"]
    pty.spawn([cpp_program] + args)


if __name__ == '__main__':
    init_system_interactive()