from flask import Flask, request, make_response
from random import randint

app = Flask(__name__)


@app.route('/')
def randomnum():
    global number
    number = randint(0, 10000)
    return str(number)


@app.route('/one/<int:num>')
def one(num):
    global number
    if num == number:
        m = '{} was correct!<br>\r\nnew number: '.format(num)
    else:
        m = '{} was wrong :(<br>\r\nnew number: '.format(num)
    number = randint(0, 10000)
    return m + str(number)


@app.route('/two/<int:num>')
def two(num):
    global number
    if num == number:
        m = '{} was correct!<br>\r\nnew number: '.format(num)
    else:
        m = '{} was wrong :(<br>\r\nnew number: '.format(num)
    number = randint(0, 10000)
    return m + str(number)


@app.route('/three/<int:num>')
def three(num):
    global number
    if num == number:
        m = '{} was correct!<br>\r\nnew number: '.format(num)
    else:
        m = '{} was wrong :(<br>\r\nnew number: '.format(num)
    number = randint(0, 10000)
    return m + str(number)


@app.route('/check/<int:num>')
def check(num):
    global number
    if num == number:
        return '{} was correct!'.format(num)
    else:
        return '{} was wrong'.format(num)


@app.route('/<polo>.html')
def marco(polo):
    """
    Nice URL to use for testing CPH's find/replace:
    http://127.0.0.1:5000/[0]find_[1]find_[2]find_[3]find_[4]find_[5]find_[6]find_[7]find_[8]find_[9]find_[10]find.html
    """
    return polo


@app.route('/cookie')
def new_cookie():
    global cookie
    resp = 'cookie received: %s<br>\r\n' % request.cookies.get('yum')
    resp += 'previous server cookie: %s<br>\r\n' % cookie
    cookie = str(randint(0, 10000))
    resp += 'new cookie set: %s' % cookie
    resp = make_response(resp)
    resp.set_cookie('yum', cookie)
    return resp


if __name__ == '__main__':
    number = randint(0, 10000)
    cookie = str(randint(0, 10000))
    app.debug = True
    app.run()
