from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///food.db'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    bills = db.relationship('Bill', backref='user', lazy=True)


dishes = db.Table('dishes',
                  db.Column('dish_id', db.Integer, db.ForeignKey(
                      'dish.id'), primary_key=True),
                  db.Column('bill_id', db.Integer, db.ForeignKey(
                      'bill.id'), primary_key=True)
                  )


class Bill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    total_dish = db.Column(db.String(50))
    amount = db.Column(db.Integer)
    is_checked = db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    dishes = db.relationship('Dish', secondary=dishes, lazy='subquery',
                             backref=db.backref('bills', lazy=True))


class Dish(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    img = db.Column(db.String(200))
    type = db.Column(db.String(50))
    price = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        # try:
        data = jwt.decode(
            token, app.config['SECRET_KEY'], algorithms=["HS256"])
        current_user = User.query.filter_by(id=data['id']).first()
        # except:
        #     return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/create_user', methods=['POST'])
def create_user():

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user created!'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify 1', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify 2', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'id': user.id, 'exp': datetime.datetime.utcnow(
        ) + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'token': token})

    return make_response('Could not verify 3', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/create_dish', methods=['POST'])
@token_required
def create_dish(current_user):

    data = request.get_json()
    new_dish = Dish(name=data['name'],
                    img=data['img'],
                    type=data['type'],
                    price=data['price'])


    db.session.add(new_dish)
    db.session.commit()

    return jsonify({'message': "dish created!"})


@app.route('/get_menu', methods=['GET'])
@token_required
def get_menu(current_user):
    dishes = Dish.query.all()
    response = []

    for dish in dishes:
        _dish = {}
        _dish['id'] = dish.id
        _dish['name'] = dish.name
        _dish['img'] = dish.img
        _dish['type'] = dish.type
        _dish['price'] = dish.price
        response.append(_dish)

    return jsonify({'dishes': response})


@app.route('/create_bill/<dish_ids>', methods=['POST'])
@token_required
def create_bill(current_user, dish_ids):
    """
    http://127.0.0.1:5000/create_bill/1,1,2
    """
    dish_ids = dish_ids.split(',')
    bill = Bill(total_dish=len(dish_ids),
            amount=0,
            is_checked=False,
            user_id=current_user.id)
                
    for id in dish_ids:
        dish = Dish.query.filter_by(id=id).one()
        bill.amount += dish.price
        bill.dishes.append(dish)

    db.session.add(bill)
    db.session.commit()

    return jsonify({'message' : "Bill created!"})


@app.route('/check_bill/<bill_id>', methods=['PATCH'])
@token_required
def check_bill(current_user, bill_id):
    bill = Bill.query.filter_by(id=bill_id).one()
    setattr(bill, 'is_checked', True)
    db.session.commit()

    return jsonify({'message' : "Bill checked!"})


@app.route('/get_all_bills', methods=['GET'])
@token_required
def get_all_bills(current_user):
    bills = Bill.query.all()
    response = []

    for bill in bills:
        _bill = {'dishes' : []}

        for dish in bill.dishes:
            _dish = {}
            _dish['id'] = dish.id
            _dish['name'] = dish.name
            _dish['img'] = dish.img
            _dish['type'] = dish.type
            _dish['price'] = dish.price
            _bill['dishes'].append(_dish)

        _bill['total_dish'] = bill.total_dish
        _bill['amount'] = bill.amount
        _bill['is_checked'] = bill.is_checked
        _bill['user_id'] = bill.user_id

        response.append(_bill)

    return jsonify({'bills' : response})


if __name__ == '__main__':
    app.run(debug=True)
