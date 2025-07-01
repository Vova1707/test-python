from db_session import create_session
from sqlalchemy import text
from datetime import datetime


def create_tables():
    connection = create_session().connection()
    connection.execute(text("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            login VARCHAR(255) NOT NULL,
            password VARCHAR(255) NOT NULL,
            is_public BOOLEAN NOT NULL DEFAULT FALSE
        );
    """))
    connection.execute(text("""
        CREATE TABLE IF NOT EXISTS tokens (
            id SERIAL PRIMARY KEY,
            token VARCHAR(255) NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
    """))
    connection.execute(text("""
        CREATE TABLE IF NOT EXISTS friendships (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (friend_id) REFERENCES users (id),
            UNIQUE (user_id, friend_id)
        );
    """))
    connection.execute(text("""
        CREATE TABLE IF NOT EXISTS Posts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            tags TEXT[],
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            likes INTEGER NOT NULL DEFAULT 0,
            dislikes INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES Users(id)
        );
    """))
    connection.commit()


def validate_token(token):
    connection = create_session().connection()
    result = connection.execute(
        text('SELECT user_id, expires_at FROM tokens WHERE token = :token'), {'token': token}
    ).fetchone()
    if result and result[-1] > datetime.now():
        return result['user_id']
    else:
        return None
    

def get_user_login(user_id):
    connection = create_session().connection()
    result = connection.execute(
        text('SELECT login FROM users WHERE id = :user_id'), {'user_id': user_id}
    ).fetchone()
    if result:
        return result[0]
    else:
        return None
    

def is_friend(user_id, author_id):
    connection = create_session().connection()
    friend = connection.execute(
        text('SELECT * FROM friends WHERE user_id = :user_id AND friend_id = :author_id'),
        {'user_id': user_id, 'author_id': author_id}
    ).fetchone()
    return friend is not None
