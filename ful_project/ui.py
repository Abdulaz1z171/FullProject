import service
from dto import UserRegisterDTO
from utils import ResponseData
from colorama import Fore


def print_response(response: ResponseData):
    color = Fore.GREEN if response.status else Fore.RED
    print(color + str(response.data) + Fore.RESET)


def print_error(error: Exception):
    print(Fore.RED + str(error) + Fore.RESET)


def menu():
    print('Login => 1')
    print('Register => 2')
    print('Logout => 3')
    print('Quit => q')
    return input('?: ')


def menu_todo():
    print('Add todo    => 1')
    print('Delete todo => 2')
    print('Edit todo   => 3')
    print('View todo   => 4')
    print('Quit        => q')
    return input('?: ')

def authentication():
    username = input('Username: ')
    password = input('Password: ')
    response: ResponseData = service.login(username, password)
    print_response(response)


def register():
    username = input('Username: ')
    password = input('Password: ')
    dto: UserRegisterDTO = UserRegisterDTO(username=username, password=password)
    response: ResponseData = service.register(dto)
    print_response(response)


def logout():
    response: ResponseData = service.logout()
    print_response(response)

# vazifa
def add_todo(): # Todo qushadi
    try:
        title = input('Todo title: ')
        response: ResponseData = service.add_todo(title)
        print_response(response)
    except Exception as e:
        print_error(e)

# vazifa
def delete_todo(): # Toda malumotlar bazasidan id orqali uchiradi
    try:
        todo_id = int(input('Enter id: '))
        response: ResponseData = service.delete_todo(todo_id)
        print_response(response)
    except Exception as e:
        print_error(e)
    

# vazifa
def edit_todo(): # Id orqali Todo ni update qiladi
    try:
        title = input('Enter title :')
        todo_type = input('Enter todo type: ')
        todo_id  = int(input('Enter todo id :'))
        response:ResponseData = service.update_todo(todo_id,title,todo_type)
        print_response(response) 
    except Exception as e:
        print_error(e)

# vazifa
def view_todo(): # Tododagi hamma malumotlarni chiqaradi
    try:
        service.select_all()
    except Exception as e:
        print_error(e)


if __name__ == '__main__':
    while True:
        choice = menu()
        if choice == '1':
            authentication()
            while True: #######################
                choice = menu_todo()
                if choice == '1':
                    add_todo()
                elif choice == '2':
                    delete_todo()
                elif choice == '3':
                    edit_todo()
                elif choice == '4':
                    view_todo()
                elif choice == 'q':
                    break ###########################
        elif choice == '2':
            register()
        elif choice == '3':
            logout()
        elif choice == 'q':
            break
