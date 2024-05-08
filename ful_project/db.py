import psycopg2
import utils

conn = psycopg2.connect(database="n42",
                        user="postgres",
                        password="temur_1336",
                        host="localhost",
                        port=5432)

cur = conn.cursor()

create_users_table = """
    create table if not exists users(
        id serial PRIMARY KEY,
        username varchar(100) not null unique,
        password varchar(255) not null,
        role varchar(20),
        status varchar(25) ,
        login_try_count int not null
    );
"""

create_todo_table = """
    create table if not exists todos(
        id serial PRIMARY KEY,
        title varchar(100) not null,
        todo_type varchar(20),
        user_id int references users(id)
    );
"""


def commit(func):
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        conn.commit()
        return result

    return wrapper


@commit
def create_tables():
    cur.execute(create_users_table)
    cur.execute(create_todo_table)


@commit
def migrate():
    insert_admin_query = '''insert into users(username,password,role,status,login_try_count)
         values (%s,%s,%s,%s,%s);
    '''
    insert_data_params = ('admin', utils.hash_password('123'), 'ADMIN', 'ACTIVE', 0)
    cur.execute(insert_admin_query, insert_data_params)


def init():
    create_tables()
    migrate()

# if __name__ == '__main__':
#     init()
