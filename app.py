from flask import Flask, jsonify, request, redirect
from flask_restful import Resource, Api, fields, reqparse, marshal_with
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager

app = Flask(__name__)
api = Api(app)

db_name = 'data.sqlite'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_name
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = "my-secret-key"

db = SQLAlchemy(app)
jwt = JWTManager(app)

resource_register = {
    'email': fields.String,
    'password': fields.String
}

resource_users = {
    'id': fields.Integer,
    'email': fields.String,
    'password': fields.String
}

resource_vaccination = {
    'id': fields.Integer,
    'name': fields.String,
    'surname': fields.String,
    'age': fields.Integer,
    'vaccine_type': fields.String,
    'dose': fields.Integer,
    'date': fields.String,
    'user_id': fields.Integer
}

class UserModel(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)

    def __init__(self, email, password):
        self.email = email
        self.password = password

    def __repr__(self):
        return f'User email is: {self.email}'

class VaccinationModel(db.Model):
    __tablename__ = 'vaccinated'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(20), nullable=False)
    surname = db.Column(db.String(30), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    vaccine_type = db.Column(db.String(20), nullable=False)
    dose = db.Column(db.Integer, nullable=False)
    date = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __init__(self, name, surname, age, vaccine_type, dose, date, user_id):
        self.name = name
        self.surname = surname
        self.age = age
        self.vaccine_type = vaccine_type
        self.dose = dose
        self.date = date
        self.user_id = user_id

    def __repr__(self):
        return f'User: {self.name} {self.username}'

registerParser = reqparse.RequestParser()
registerParser.add_argument('email', type=str, required=True, help='Email should be string')
registerParser.add_argument('password', type=str, required=True, help='Password should be string')

userParser = reqparse.RequestParser()
userParser.add_argument('email', type=str, help='Email should be string')
userParser.add_argument('password', type=str, help='Password should be string')

vaccineParser = reqparse.RequestParser()
vaccineParser.add_argument('name', type=str, help='Name should be string')
vaccineParser.add_argument('surname', type=str, help='Surname should be string')
vaccineParser.add_argument('age', type=int, help='Age should be integer')
vaccineParser.add_argument('vaccine_type', type=str, help='Vaccine type should be string')
vaccineParser.add_argument('dose', type=int, help='Dose should be integer')
vaccineParser.add_argument('date', type=str, help='Date should be string')
vaccineParser.add_argument('user_id', type=int, help='User id should be string')

class Register(Resource):
    # @marshal_with(resource_register)
    def post(self):
        args = registerParser.parse_args()
        user = UserModel(email=args['email'], password=generate_password_hash(args['password']))
        db.session.add(user)
        db.session.commit()
        return 'You are registered!', 201

class Auth(Resource):
    def post(self):
        email = request.json.get('email', None)
        password = request.json.get('password', None)
        user = UserModel.query.filter_by(email=email).first()
        if user == None:
            return "{'msg': 'Email was not found'}"
        if email != user.email and check_password_hash(user.password, password) == False:
            return jsonify({'msg': 'Bad email or password'}), 401
        access_token = create_access_token(identity=email)
        return jsonify(access_token=access_token)

class User(Resource):
    @marshal_with(resource_users)
    @jwt_required()
    def get(self, user_id):
        if user_id == 000:
            return UserModel.query.all()
        user = UserModel.query.filter_by(id=user_id).first()
        return user

    # @marshal_with(resource_users)
    @jwt_required()
    def post(self, user_id):
        args = userParser.parse_args()
        password = generate_password_hash(args['password'])
        user = UserModel(email=args['email'], password=password)
        db.session.add(user)
        db.session.commit()
        return f'Created user with id {user_id}'

    # @marshal_with(resource_users)
    @jwt_required()
    def put(self, user_id):
        args = userParser.parse_args()
        user = UserModel.query.filter_by(id=user_id).first()
        password = generate_password_hash(args['password'])
        if user == None:
            user = UserModel(email=args['email'], password=password)
        else:
            user.email = args['email']
            user.password = password
        db.session.add(user)
        db.session.commit()
        return f'Edited user with id {user_id}'

    @jwt_required()
    def delete(self, user_id):
        user = UserModel.query.filter_by(id=user_id).first()
        db.session.delete(user)
        db.session.commit()
        return f'Deleted user with id {user_id}'

class Vaccine(Resource):
    @marshal_with(resource_vaccination)
    @jwt_required()
    def get(self, vaccine_id):
        if vaccine_id == 777:
            return VaccinationModel.query.all()
        vaccine = VaccinationModel.query.filter_by(id=vaccine_id).first()
        return vaccine

    # @marshal_with(resource_vaccination)
    @jwt_required()
    def post(self, vaccine_id):
        args = vaccineParser.parse_args()
        vaccine = VaccinationModel(name=args['name'], surname=args['surname'], age=args['age'],
                                   vaccine_type=args['vaccine_type'],
                                   dose=args['dose'], date=args['date'], user_id=args['user_id'])
        db.session.add(vaccine)
        db.session.commit()
        return f'Created vaccinated person with id {vaccine_id}'

    # @marshal_with(resource_vaccination)
    @jwt_required()
    def put(self, vaccine_id):
        args = vaccineParser.parse_args()
        vaccine = VaccinationModel.query.filter_by(id=vaccine_id).first()
        if vaccine == None:
            vaccine = VaccinationModel(name=args['name'], surname=args['surname'], age=args['age'],
                                       vaccine_type=args['vaccine_type'],
                                       dose=args['dose'], date=args['date'], user_id=args['user_id'])
        else:
            vaccine.name = args['name']
            vaccine.surname = args['surname']
            vaccine.age = args['age']
            vaccine.vaccine_type = args['vaccine_type']
            vaccine.dose = args['dose']
            vaccine.date = args['date']
            vaccine.user_id = args['user_id']

        db.session.add(vaccine)
        db.session.commit()
        return f'Edited vaccinated person with id {vaccine_id}'

    @jwt_required()
    def delete(self, vaccine_id):
        vaccine = VaccinationModel.query.filter_by(id=vaccine_id).first()
        db.session.delete(vaccine)
        db.session.commit()
        return f'Deleted vaccinated person with id {vaccine_id}'

api.add_resource(Register, '/register')
api.add_resource(Auth, '/login')
api.add_resource(User, '/user/<int:user_id>')
api.add_resource(Vaccine, '/vaccine/<int:vaccine_id>')

@app.route('/')
def home():
    return redirect('https://github.com/gigaamiridze/First-API')

@app.before_first_request
def create_table():
    import data
    data.create_database()

if __name__ == '__main__':
    app.run(debug=True, port=7777)