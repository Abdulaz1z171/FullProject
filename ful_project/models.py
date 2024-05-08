import enum


class TodoType(enum.Enum):
    SHOPPING = 'SHOPPING'
    PERSONAL = 'PERSONAL'
    LEARN = 'LEARN'


class UserStatus(enum.Enum):
    INACTIVE = 'INACTIVE'
    ACTIVE = 'ACTIVE'
    BLOCKED = 'BLOCKED'


class UserRole(enum.Enum):
    SUPER_ADMIN = 'SUPER_ADMIN'
    USER = 'USER'
    ADMIN = 'ADMIN'


class User:
    def __init__(self,
                 username: str,
                 password: str,
                 user_id: int | None = None,
                 role: UserRole | None = None,
                 status: UserStatus | None = None,
                 login_try_count: int | None = None
                 ):
        self.id = user_id
        self.username = username
        self.password = password
        self.role = role or UserRole.USER.value
        self.status = status or UserStatus.INACTIVE.value
        self.login_try_count = login_try_count or 0

    @staticmethod
    def from_tuple(args: tuple):
        return User(user_id=args[0],
                    username=args[1],
                    password=args[2],
                    role=args[3],
                    status=args[4],
                    login_try_count=args[5])

    def __repr__(self) -> str:
        return f'{self.id} - {self.username} - {self.role}'


class Todo:
    def __init__(self,
                 title: str,
                 user_id: int,
                 todo_id: int | None = None,
                 todo_type: TodoType | None = None,
                 ):
        self.id = todo_id
        self.title = title
        self.user_id = user_id
        self.todo_type = todo_type or TodoType.PERSONAL.value

    def __repr__(self) -> str:
        return f' Title: {self.title} => Todo type: {self.todo_type} => Todo id connect with user id: {self.user_id}'
