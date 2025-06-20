from flask import Blueprint, jsonify, request
from db_session import create_session
from sqlalchemy import text
import re
import uuid
import datetime


api = Blueprint('api', __name__, url_prefix='/api')


@api.route('/ping', methods=['GET'])
def ping():
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
    print(token)
    return jsonify({'token': token}), 200


@api.route('/me/profile', methods=['GET', 'PATCH'])
def profile():
    token = request.headers.get('Authorization').replace('Bearer ', '')
    connection = create_session().connection()

    user_id = connection.execute(
        text('SELECT user_id FROM tokens WHERE token = :token'), {'token': token}
    ).fetchone()

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

