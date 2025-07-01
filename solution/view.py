from flask import Blueprint, jsonify, request
from db_session import create_session
from sqlalchemy import text
import re
import uuid
import datetime
from func import validate_token, get_user_login, create_tables, is_friend


api = Blueprint('api', __name__, url_prefix='/api')


@api.route('/ping', methods=['GET'])
def ping():
    create_tables()
    return jsonify({'status': 'ok'}), 200


@api.route('/countries', methods=['GET'])
def countries():
    connection = create_session().connection()
    region = request.args.get('region')
    if not region:
        countries = connection.execute(
            text('SELECT * FROM countries')
        ).fetchall()
    else:
        params = {'region': region}
        countries = connection.execute(
            text('SELECT * FROM countries WHERE region = :region'), params
        ).fetchall()
    cn = []
    for contry in countries:
        cn.append(
            {
                'name': contry[1],
                'alpha2': contry[2],
                'alpha3': contry[3],
                'region': contry[4],
            }
        )
    return cn, 200


@api.route('/countries/<string:alpha2>', methods=['GET'])
def countries_alpfa2(alpha2):
    connection = create_session().connection()
    params = {'alpha2': alpha2}
    countrie = connection.execute(
        text('SELECT * FROM countries WHERE alpha2 = :alpha2'), params
    ).fetchone()
    print(countrie)
    st = {
        'name': countrie[1],
        'alpha2': countrie[2],
        'alpha3': countrie[3],
        'region': countrie[4],
    }
    return st, 200


@api.route('auth/register', methods=['POST'])
def register():
    data = request.get_json()

    login = data.get('login')
    email = data.get('email')
    password = data.get('password')
    countryCode = data.get('countryCode')
    isPublic = data.get('isPublic')
    phone = data.get('phone')
    image = data.get('image')
    connection = create_session().connection()

    event = {
        # Проверка, что все поля заполнены правильно
        all([login, email, password, countryCode, isPublic]) and
        all([isinstance(login, str), isinstance(email, str), isinstance(password, str), 
            isinstance(countryCode, str),isinstance(isPublic, bool)]):
        ['Неправильный тип данных', 400],
        # Проверка длинны полей и пароля
        not (len(login) > 30 or len(email) > 50 or len(countryCode) > 2 or len(phone) > 20)
        and  not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@#$%^&+=])[A-Za-z0-9@#$%^&+=]{8,}$', password):
        ['Неправильный тип3 данных', 400],
        # Проверка существования страны
        connection.execute(
            text('SELECT * FROM countries WHERE alpha2 = :alpha2'),
            {'alpha2': countryCode},
        ).fetchone(): ['Неправильный тип4 данных', 400],
        # Проверка уникальности авторизационных данных
        not connection.execute(
            text(
                'SELECT * FROM users WHERE login = :login OR email = :email OR phone = :phone'
            ),
            {'login': login, 'email': email, 'phone': phone},
        ).fetchone(): [
            'Нарушено требование на уникальность авторизационных данных пользователей',
            409,
        ],
    }

    for key, value in event.items():
        if not key:
            print(connection.execute(
            text(
                'SELECT * FROM users WHERE login = :login OR email = :email OR phone = :phone'
            ),
            {'login': login, 'email': email, 'phone': phone},
        ).fetchone())
            return value[0], value[1]

    # Создаём нового пользователя
    user = connection.execute(
        text(
            'INSERT INTO users (login, email, password, country_code, is_public, phone, image) VALUES'
            '(:login, :email, :password, :countryCode, :isPublic, :phone, :image) RETURNING id, login, email, country_code, is_public, phone, image'
        ),
        {
            'login': login,
            'email': email,
            'password': password,
            'countryCode': countryCode,
            'isPublic': isPublic,
            'phone': phone,
            'image': image,
        },
    ).fetchone()[0:7]

    connection.commit()

    return (
        jsonify(
            {
                'profile': {
                    'login': user[1],
                    'email': user[2],
                    'countryCode': user[3],
                    'isPublic': user[4],
                    'phone': user[5],
                }
            }
        ),
        201,
    )


@api.route('/auth/sign-in', methods=['POST'])
def sign_in():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')
    connection = create_session().connection()

    if not login or not password:
        return jsonify({'error': 'Логин и пароль обязательны'}), 401

    user = connection.execute(
        text('SELECT * FROM users WHERE login = :login'), {'login': login}
    ).fetchone()
    print(user)
    if not user:
        return jsonify({'error': 'Пользователь с указанным логином и паролем не найден'}), 401

    # Генерируем токен и время его действия
    token = str(uuid.uuid4())
    expires_at = datetime.datetime.now() + datetime.timedelta(hours=1)

    # Сохраняем токен в базе данных
    connection.execute(
        text(
            'INSERT INTO tokens (user_id, token, expires_at) VALUES (:user_id, :token, :expires_at)'
        ),
        {'user_id': user.id, 'token': token, 'expires_at': expires_at},
    )
    connection.commit()
    #print(token)
    return jsonify({'token': token}), 200


@api.route('/me/profile', methods=['GET', 'PATCH'])
def me():
    token = request.headers.get('Authorization').replace('Bearer ', '')
    connection = create_session().connection()

    user_id = validate_token(token)

    if not user_id:
        return jsonify({'error': 'Токен неверен'}), 401

    if request.method == 'GET':
        user = connection.execute(
            text('SELECT * FROM users WHERE id = :user_id'), {'user_id': user_id[0]}
        ).fetchone()
        return (
        jsonify(
            {
                'login': user[1],
                'email': user[2],
                'countryCode': user[3],
                'isPublic': user[4],
                'phone': user[5],
            }
        ),
        200,
    )

    elif request.method == 'PATCH':
        data = request.get_json()
        update_query = []
        update_values = {}

        for key, value in data.items():
            update_query.append(f"{key} = :{key}")
            update_values[key] = value

        update_query = ', '.join(update_query)

        connection.execute(
            text(f"UPDATE users SET {update_query} WHERE id = :user_id"),
            {**update_values, 'user_id': user_id[0]},
        )
        connection.commit()

        return jsonify({'message': 'Профиль обновлен'}), 200


@api.route('/profiles/<string:user_login>', methods=['POST'])
def profiles(user_login):
    connection = create_session().connection()
    other_user = connection.execute(
        text('SELECT * FROM users WHERE login = :login'), {'login': user_login}
    ).fetchone()

    token = request.headers.get('Authorization').replace('Bearer ', '')
    user_id = validate_token(token)

    if not other_user:
        return jsonify({'error': 'User not found'}), 403

    if token and user_id:
        if other_user['is_public']:
            return jsonify(other_user), 200
        elif user_id == other_user['id']:
            return jsonify(other_user), 200
        else:
            return jsonify({'error': 'Forbidden'}), 403
    else:
        return jsonify({'error': 'Invalid token'}), 401


@api.route('/me/updatePassword', methods=['POST'])
def update_password():
    connection = create_session().connection()
    token = request.headers.get('Authorization').replace('Bearer ', '')
    user_id = validate_token(token)

    data = request.get_json()
    old_password = data.get('oldPassword')
    new_password = data.get('newPassword')

    if not user_id:
        return jsonify({'error': 'User not found'}), 404
    
    user = connection.execute(
        text('SELECT * FROM users WHERE id = :user_id'), {'user_id': user_id}
    ).fetchone()

    if not user['password'] == old_password:
        return jsonify({'error': 'Invalid old password'}), 403

    connection.execute(
        text('UPDATE users SET password = :new_password WHERE id = :user_id'),
        {'new_password': new_password, 'user_id': user_id}
    )
    connection.commit()

    return jsonify({'status': 'ok'}), 200



@api.route('/friends/add', methods=['POST'])
def friends_add():
    connection = create_session().connection()
    token = request.headers.get('Authorization').replace('Bearer ', '')
    user_id = validate_token(token)

    data = request.get_json()
    friend_login = data.get('login')

    if not user_id:
        return jsonify({'error': 'Invalid token'}), 401

    if friend_login == get_user_login(user_id):
        return jsonify({'status': 'ok'}), 200

    friend = connection.execute(
        text('SELECT * FROM users WHERE login = :login'), {'login': friend_login}
    ).fetchone()

    if not friend:
        return jsonify({'error': 'User not found'}), 404

    existing_friendship = connection.execute(
        text('SELECT * FROM friendships WHERE user_id = :user_id AND friend_id = :friend_id'),
        {'user_id': user_id, 'friend_id': friend['id']}
    ).fetchone()

    if existing_friendship:
        return jsonify({'status': 'ok'}), 200

    connection.execute(
        text('INSERT INTO friendships (user_id, friend_id, created_at) VALUES (:user_id, :friend_id, :created_at)'),
        {'user_id': user_id, 'friend_id': friend['id'], 'created_at': datetime.now()}
    )
    connection.commit()

    return jsonify({'status': 'ok'}), 200




@api.route('/friends/remove', methods=['POST'])
def friends_remove():
    connection = create_session().connection()
    token = request.headers.get('Authorization').replace('Bearer ', '')
    user_id = validate_token(token)

    data = request.get_json()
    friend_login = data.get('login')

    if not user_id:
        return jsonify({'error': 'Invalid token'}), 401

    friend = connection.execute(
        text('SELECT * FROM users WHERE login = :login'), {'login': friend_login}
    ).fetchone()

    if not friend:
        return jsonify({'status': 'ok'}), 200

    existing_friendship = connection.execute(
        text('SELECT * FROM friendships WHERE user_id = :user_id AND friend_id = :friend_id'),
        {'user_id': user_id, 'friend_id': friend['id']}
    ).fetchone()

    if not existing_friendship:
        return jsonify({'status': 'ok'}), 200

    connection.execute(
        text('DELETE FROM friendships WHERE user_id = :user_id AND friend_id = :friend_id'),
        {'user_id': user_id, 'friend_id': friend['id']}
    )
    connection.commit()

    return jsonify({'status': 'ok'}), 200


@api.route('/friends', methods=['GET'])
def friends_list():
    connection = create_session().connection()
    token = request.headers.get('Authorization').replace('Bearer ', '')
    user_id = validate_token(token)

    if not user_id:
        return jsonify({'error': 'Invalid token'}), 401

    limit = request.args.get('limit', 10, type=int)
    offset = request.args.get('offset', 0, type=int)

    friends = connection.execute(
        text('''
            SELECT user.login, friendships.created_at
            FROM friendships
            JOIN users ON friendships.friend_id = users.id
            WHERE friendships.user_id = :user_id
            ORDER BY friendships.created_at DESC
        '''),
        {'user_id': user_id, 'limit': limit, 'offset': offset}
    ).fetchall()

    return jsonify([{'login': friend[0], 'addedAt': friend[1].isoformat() + 'Z'} for friend in friends]), 200



"""----------------ПОСТЫ-------------------------------"""
@api.route('/posts/new', methods=['POST'])
def submit_post():
    connection = create_session().connection()
    token = request.headers.get('Authorization').replace('Bearer ', '')
    user_id = validate_token(token)

    if not user_id:
        return jsonify({'error': 'Invalid token'}), 401

    data = request.get_json()
    content = data.get('content')
    tags = data.get('tags')

    post_id = connection.execute(
        text('INSERT INTO posts (user_id, content, tags) VALUES (:user_id, :content, :tags) RETURNING id'),
        {'user_id': user_id, 'content': content, 'tags': tags}
    ).fetchone()[0]

    connection.commit()

    return jsonify({'id': post_id, 'content': content, 'tags': tags, 'created_at': datetime.now().isoformat() + 'Z'}), 200



@api.route('/posts/int:post_id', methods=['GET']) 
def get_post_by_id(post_id): 
    connection = create_session().connection() 
    token = request.headers.get('Authorization').replace('Bearer ', '') 
    user_id = validate_token(token)
    if not user_id:
        return jsonify({'error': 'Invalid token'}), 401

    post = connection.execute(
        text('SELECT * FROM posts WHERE id = :post_id'),
        {'post_id': post_id}
    ).fetchone()

    if not post:
        return jsonify({'error': 'Post not found'}), 404

    if post['user_id'] != user_id and not is_friend(user_id, post['user_id']):
        return jsonify({'error': 'Access denied'}), 404

    return jsonify({
        'id': post['id'],
        'content': post['content'],
        'tags': post['tags'],
        'created_at': post['created_at'].isoformat() + 'Z'
    }), 200


@api.route('/posts/feed/my', methods=['GET']) 
def get_my_feed(): 
    connection = create_session().connection() 
    token = request.headers.get('Authorization').replace('Bearer ', '') 
    user_id = validate_token(token)
    if not user_id:
        return jsonify({'error': 'Invalid token'}), 401

    limit = request.args.get('limit', default=10, type=int)
    offset = request.args.get('offset', default=0, type=int)

    posts = connection.execute(
        text('SELECT * FROM posts WHERE user_id = :user_id ORDER BY created_at DESC LIMIT :limit OFFSET :offset'),
        {'user_id': user_id, 'limit': limit, 'offset': offset}
    ).fetchall()

    return jsonify([{
        'id': post['id'],
        'content': post['content'],
        'tags': post['tags'],
        'created_at': post['created_at'].isoformat() + 'Z'
    } for post in posts]), 200


@api.route('/posts/feed/string:login', methods=['GET']) 
def get_feed_by_others(login): 
    connection = create_session().connection() 
    token = request.headers.get('Authorization').replace('Bearer ', '') 
    user_id = validate_token(token)
    if not user_id:
        return jsonify({'error': 'Invalid token'}), 401

    limit = request.args.get('limit', default=10, type=int)
    offset = request.args.get('offset', default=0, type=int)

    user = connection.execute(
        text('SELECT * FROM users WHERE login = :login'),
        {'login': login}
    ).fetchone()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    if not user['isPublic'] and not is_friend(user_id, user['id']):
        return jsonify({'error': 'Access denied'}), 404

    posts = connection.execute(
        text('SELECT * FROM posts WHERE user_id = :user_id ORDER BY created_at DESC LIMIT :limit OFFSET :offset'),
        {'user_id': user['id'], 'limit': limit, 'offset': offset}
    ).fetchall()

    return jsonify([{
        'id': post['id'],
        'content': post['content'],
        'tags': post['tags'],
        'created_at': post['created_at'].isoformat() + 'Z'
    } for post in posts]), 200


"""----------------ЛАЙКИ И ДИСЛАЙКИ-------------------------------"""
@api.route('/posts/int:post_id/like', methods=['POST']) 
def like_post(post_id): 
    connection = create_session().connection() 
    token = request.headers.get('Authorization').replace('Bearer ', '') 
    user_id = validate_token(token)

    if not user_id:
        return jsonify({'error': 'Invalid token'}), 401

    post = connection.execute(
        text('SELECT * FROM posts WHERE id = :post_id'),
        {'post_id': post_id}
    ).fetchone()

    if not post:
        return jsonify({'error': 'Post not found'}), 404

    if post['user_id'] != user_id and not is_friend(user_id, post['user_id']):
        return jsonify({'error': 'Access denied'}), 404
    
    connection.execute(text('UPDATE posts SET likes = likes + 1 WHERE id = :post_id'), {'post_id': post_id})

    connection.commit()

    return jsonify({
        'id': post[0],
        'content': post[2],
        'created_at': post[3].isoformat() + 'Z',
        'likes': post[-2] + 1,
        'dislikes': post[-1]
    }), 200


@api.route('/posts/int:post_id/dislike', methods=['POST']) 
def dislike_post(post_id): 
    connection = create_session().connection() 
    token = request.headers.get('Authorization').replace('Bearer ', '') 
    user_id = validate_token(token)

    if not user_id:
        return jsonify({'error': 'Invalid token'}), 401

    post = connection.execute(
        text('SELECT * FROM posts WHERE id = :post_id'),
        {'post_id': post_id}
    ).fetchone()

    if not post:
        return jsonify({'error': 'Post not found'}), 404

    if post['user_id'] != user_id and not is_friend(user_id, post['user_id']):
        return jsonify({'error': 'Access denied'}), 404
    
    connection.execute(text('UPDATE posts SET dislikes = dislikes + 1 WHERE id = :post_id'), {'post_id': post_id})

    connection.commit()

    return jsonify({
        'id': post[0],
        'content': post[2],
        'created_at': post[3].isoformat() + 'Z',
        'likes': post[-2],
        'dislikes': post[-1] + 1,
    }), 200