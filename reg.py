import requests
import pty

def init_registrator_CLI():
    username = input("Введите логин регистратора: ") or "reg" #todo
    password = input("Введите пароль регистратора: ") or "123" #todo
    
    url = "http://0.0.0.0:5050/registrator"
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
    
    cpp_program = response_data["cpp_program"]
    pty.spawn([cpp_program])
    

if __name__ == '__main__':
    init_registrator_CLI()