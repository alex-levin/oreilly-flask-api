import os
from datetime import datetime
from dateutil import parser as datetime_parser
from dateutil.tz import tzutc
### added for password authentication
### https://blog.miguelgrinberg.com/post/restful-authentication-with-flask
from werkzeug.security import generate_password_hash, check_password_hash
### added g - see https://flask.palletsprojects.com/en/1.1.x/api/#flask.g
### https://stackoverflow.com/questions/30514749/what-is-the-g-object-in-this-flask-code
from flask import Flask, url_for, jsonify, request, g
from flask_sqlalchemy import SQLAlchemy
### added from Flask-HTTPAuth extension
### https://github.com/miguelgrinberg/Flask-HTTPAuth
### https://flask-httpauth.readthedocs.io/en/latest/
from flask_httpauth import HTTPBasicAuth
from utils import split_url


basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, '../data.sqlite')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
### handler for basic authentication comes from Flask-HTTPAuth extension
### https://flask-httpauth.readthedocs.io/en/latest/
auth = HTTPBasicAuth()

class ValidationError(ValueError):
    pass

# added error handler decorators from Flask

# Flask error handler can be used not only for standard errors but also for custom exceptions:
@app.errorhandler(ValidationError)
def bad_request(e):
    response = jsonify({'status': 400, 'error': 'bad request',
                        'message': e.args[0]})
    response.status_code = 400
    return response

'''
wrong URL: http://localhost/5000/cust/
returns 
{
  "error": "not found", 
  "message": "invalid resource URI", 
  "status": 404
}

if no error handlers, returns
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
'''
@app.errorhandler(404)
def not_found(e):
    response = jsonify({'status': 404, 'error': 'not found',
                        'message': 'invalid resource URI'})
    response.status_code = 404
    return response

# example: trying to delete customer but there is no delete method
@app.errorhandler(405)
def method_not_supported(e):
    response = jsonify({'status': 405, 'error': 'method not supported',
                        'message': 'the method is not supported'})
    response.status_code = 405
    return response

@app.errorhandler(500)
def internal_server_error(e):
    response = jsonify({'status': 500, 'error': 'internal server error',
                        'message': e.args[0]})
    response.status_code = 500
    return response

### new model to add users to the database
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        # generate_password_hash function comes with the werkzeug web server utility
        # which is a dependency of Flask
        # it comes with authentication and password hashing functions
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        # self.password_hash is also werkzeug function
        return check_password_hash(self.password_hash, password)
###

class Customer(db.Model):
    __tablename__ = 'customers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True)
    # one-to-many relationship for orders
    orders = db.relationship('Order', backref='customer', lazy='dynamic')

    def get_url(self):
        # _external=True generates full URL
        return url_for('get_customer', id=self.id, _external=True)

    def export_data(self):
        return {
            'self_url': self.get_url(),
            'name': self.name,
            # _external=True generates full URL
            'orders_url': url_for('get_customer_orders', id=self.id,
                                  _external=True)
        }

    def import_data(self, data):
        try:
            self.name = data['name']
        except KeyError as e:
            # using exception handling here to avoid error checking in routes
            raise ValidationError('Invalid customer: missing ' + e.args[0])
        return self


class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True)
    items = db.relationship('Item', backref='product', lazy='dynamic')

    def get_url(self):
        return url_for('get_product', id=self.id, _external=True)

    def export_data(self):
        return {
            'self_url': self.get_url(),
            'name': self.name
        }

    def import_data(self, data):
        try:
            self.name = data['name']
        except KeyError as e:
            raise ValidationError('Invalid product: missing ' + e.args[0])
        return self


class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    # relationship to the customer
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'),
                            index=True)
    date = db.Column(db.DateTime, default=datetime.now)
    # relationship to items
    items = db.relationship('Item', backref='order', lazy='dynamic',
                            # when the order is delete, all associated itmes will also be deleted
                            cascade='all, delete-orphan')

    def get_url(self):
        return url_for('get_order', id=self.id, _external=True)

    def export_data(self):
        return {
            'self_url': self.get_url(),
            'customer_url': self.customer.get_url(),
            # UTC time object
            'date': self.date.isoformat() + 'Z',
            'items_url': url_for('get_order_items', id=self.id,
                                 _external=True)
        }

    def import_data(self, data):
        try:
            # datetime_parser.parse(data['date']) return time object that has timezone in it
            # the client can send any time zone, but we don't want to store timezone in the database
            # so that all time object are consistent
            # astimezone(tzutc()) converts time to UTC
            # replace(tzinfo=None) removes time zone from the time object
            self.date = datetime_parser.parse(data['date']).astimezone(
                tzutc()).replace(tzinfo=None)
        except KeyError as e:
            raise ValidationError('Invalid order: missing ' + e.args[0])
        return self


class Item(db.Model):
    __tablename__ = 'items'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), index=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'),
                           index=True)
    quantity = db.Column(db.Integer)

    def get_url(self):
        return url_for('get_item', id=self.id, _external=True)

    def export_data(self):
        return {
            'self_url': self.get_url(),
            'order_url': self.order.get_url(),
            'product_url': self.product.get_url(),
            'quantity': self.quantity
        }

    def import_data(self, data):
        try:
            # split_url: https://gist.github.com/miguelgrinberg/9908687
            # reverse of url_for(): decompose a URL into its parts
            # defined in the utils.py module 
            endpoint, args = split_url(data['product_url'])
            self.quantity = int(data['quantity'])
        except KeyError as e:
            raise ValidationError('Invalid order: missing ' + e.args[0])
        if endpoint != 'get_product' or not 'id' in args:
            raise ValidationError('Invalid product URL: ' +
                                  data['product_url'])
        self.product = Product.query.get(args['id'])
        if self.product is None:
            raise ValidationError('Invalid product URL: ' +
                                  data['product_url'])
        return self

### Flask-HTTPAuth auth (line 25) provides verify_password decorator - password verification function
### https://flask-httpauth.readthedocs.io/en/latest/
### https://blog.miguelgrinberg.com/post/restful-authentication-with-flask
'''
Using Flask-HTTPAuth an endpoint is protected by adding the login_required decorator to it (line 262).
Flask-HTTPAuth needs to be given some more information to know how to validate user credentials,
and for this there are several options depending on the level of security implemented by the application.
The option that gives the maximum flexibility is implemented through the verify_password callback, which
is given the username and password and is supposed to return True if the combination is valid or False if not.
Flask-HTTPAuth invokes this callback function whenever it needs to validate a username and password pair.
Thie need arrives when an endpoint is protected by the login_required decorator.
If defined, this callback function will be called by Flask-HTTPAuth to verify that the username and
password combination provided by the client are valid. The callback function takes two arguments,
the username and the password and must return True or False.
'''
@auth.verify_password
def verify_password(username, password):
    # getting user from the database
    # g is a context object from Flask. g is enabled when a request is received.
    # g has a request scope. we will store user in it so that routes don't need to
    # retrieve user again from the database - they will get it from g.  
    g.user = User.query.filter_by(username=username).first()
    if g.user is None:
        return False
    # if user is found - verify password    
    return g.user.verify_password(password)

'''
before_request decorator: https://flask.palletsprojects.com/en/1.1.x/api/#application-object
password verification verify_password() will run before request handler before_request()
@auth.login_required decorator will call verify_password() decorated with @auth.verify_password
'''
@app.before_request
@auth.login_required
def before_request():
    pass

# https://flask-httpauth.readthedocs.io/en/latest/
@auth.error_handler
def unauthorized():
    response = jsonify({'status': 401, 'error': 'unauthorized',
                        'message': 'please authenticate'})
    response.status_code = 401
    return response
###


@app.route('/customers/', methods=['GET'])
def get_customers():
    print('in get_custommers(): ', g.user)
    return jsonify({'customers': [customer.get_url() for customer in
                                  Customer.query.all()]})

@app.route('/customers/<int:id>', methods=['GET'])
def get_customer(id):
    return jsonify(Customer.query.get_or_404(id).export_data())

@app.route('/customers/', methods=['POST'])
def new_customer():
    customer = Customer()
    customer.import_data(request.json)
    db.session.add(customer)
    db.session.commit()
    return jsonify({}), 201, {'Location': customer.get_url()}

@app.route('/customers/<int:id>', methods=['PUT'])
def edit_customer(id):
    customer = Customer.query.get_or_404(id)
    customer.import_data(request.json)
    db.session.add(customer)
    db.session.commit()
    return jsonify({})


@app.route('/products/', methods=['GET'])
def get_products():
    return jsonify({'products': [product.get_url() for product in
                                 Product.query.all()]})

@app.route('/products/<int:id>', methods=['GET'])
def get_product(id):
    return jsonify(Product.query.get_or_404(id).export_data())

@app.route('/products/', methods=['POST'])
def new_product():
    product = Product()
    product.import_data(request.json)
    db.session.add(product)
    db.session.commit()
    return jsonify({}), 201, {'Location': product.get_url()}

@app.route('/products/<int:id>', methods=['PUT'])
def edit_product(id):
    product = Product.query.get_or_404(id)
    product.import_data(request.json)
    db.session.add(product)
    db.session.commit()
    return jsonify({})



@app.route('/orders/', methods=['GET'])
def get_orders():
    return jsonify({'orders': [order.get_url() for order in Order.query.all()]})

@app.route('/customers/<int:id>/orders/', methods=['GET'])
def get_customer_orders(id):
    customer = Customer.query.get_or_404(id)
    return jsonify({'orders': [order.get_url() for order in
                               customer.orders.all()]})

@app.route('/orders/<int:id>', methods=['GET'])
def get_order(id):
    return jsonify(Order.query.get_or_404(id).export_data())

@app.route('/customers/<int:id>/orders/', methods=['POST'])
def new_customer_order(id):
    customer = Customer.query.get_or_404(id)
    order = Order(customer=customer)
    order.import_data(request.json)
    db.session.add(order)
    db.session.commit()
    return jsonify({}), 201, {'Location': order.get_url()}

@app.route('/orders/<int:id>', methods=['PUT'])
def edit_order(id):
    order = Order.query.get_or_404(id)
    order.import_data(request.json)
    db.session.add(order)
    db.session.commit()
    return jsonify({})

@app.route('/orders/<int:id>', methods=['DELETE'])
def delete_order(id):
    order = Order.query.get_or_404(id)
    db.session.delete(order)
    db.session.commit()
    return jsonify({})


@app.route('/orders/<int:id>/items/', methods=['GET'])
def get_order_items(id):
    order = Order.query.get_or_404(id)
    return jsonify({'items': [item.get_url() for item in order.items.all()]})

@app.route('/items/<int:id>', methods=['GET'])
def get_item(id):
    return jsonify(Item.query.get_or_404(id).export_data())

@app.route('/orders/<int:id>/items/', methods=['POST'])
def new_order_item(id):
    order = Order.query.get_or_404(id)
    item = Item(order=order)
    item.import_data(request.json)
    db.session.add(item)
    db.session.commit()
    return jsonify({}), 201, {'Location': item.get_url()}

@app.route('/items/<int:id>', methods=['PUT'])
def edit_item(id):
    item = Item.query.get_or_404(id)
    item.import_data(request.json)
    db.session.add(item)
    db.session.commit()
    return jsonify({})

@app.route('/items/<int:id>', methods=['DELETE'])
def delete_item(id):
    item = Item.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    return jsonify({})

if __name__ == '__main__':
    db.create_all()
    ### added
    # create a development user
    if User.query.get(1) is None:
        u = User(username='john')
        u.set_password('cat')
        db.session.add(u)
        db.session.commit()
    ###
    app.run(debug=True)
