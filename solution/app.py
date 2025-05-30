import os
from flask import Flask
from dotenv import load_dotenv
from db_session import global_init


from view import api


app = Flask(__name__)
app.register_blueprint(api)


if __name__ == "__main__":
    load_dotenv()
    global_init(f"postgresql://{os.getenv('POSTGRES_USERNAME')}:{os.getenv('POSTGRES_PASSWORD')}@localhost:{os.getenv('POSTGRES_PORT', '5432')}/{os.getenv('POSTGRES_DATABASE')}")
    app.run(port=5001)
