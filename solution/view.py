from flask import Blueprint, jsonify, request
from db_session import create_session
from sqlalchemy import text



api = Blueprint('api', __name__, url_prefix='/api')



@api.route('/ping', methods=['GET'])
def ping():
    return jsonify({"status": "ok"}), 200



@api.route('/countries', methods=['GET'])
def countries():
    connection = create_session().connection()
    region = request.args.get('region')
    if not region:
        countries = connection.execute(text("SELECT * FROM countries")).fetchall()
    else:
        params = {'region': region}
        countries = connection.execute(text("SELECT * FROM countries WHERE region = :region"), params).fetchall()
    cn = []
    for contry in countries:
        cn.append({"name": contry[1], "alpha2": contry[2], "alpha3": contry[3], "region": contry[4]})
    return cn, 200



@api.route('/countries/<string:alpha2>', methods=['GET'])
def countries_alpfa2(alpha2):
    connection = create_session().connection()
    params = {'alpha2': alpha2}
    countrie = connection.execute(text("SELECT * FROM countries WHERE alpha2 = :alpha2"), params).fetchone()
    print(countrie)
    st = {"name": countrie[1], "alpha2": countrie[2], "alpha3": countrie[3], "region": countrie[4]}
    return st, 200