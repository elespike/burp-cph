from SimpleHTTPServer import SimpleHTTPRequestHandler
from json             import loads
from random           import randint
from re               import search as re_search
from urllib           import unquote


class TinyHandler(SimpleHTTPRequestHandler, object):
    the_number = randint(1, 99999)
    def __init__(self, *args, **kwargs):
        self.protocol_version = 'HTTP/1.1'
        super(TinyHandler, self).__init__(*args, **kwargs)

    @staticmethod
    def normalize(number):
        try:
            number = int(number)
        except ValueError:
            return randint(1, 99999)
        if number == 0:
            return 1
        if number < 0:
            number = abs(number)
        while number > 99999:
            number = number / 10
        return number

    def do_GET(self):
        headers = {}
        response_body = 'https://github.com/elespike/burp-cph/wiki/00.-Interactive-demos'

        if self.path == '/':
            headers['Content-Type'] = 'text/html'
            response_body = '<h2>Welcome!</h2>Please <a href="https://github.com/elespike/burp-cph/wiki/00.-Interactive-demos">visit the Wiki </a> for instructions.'

        if self.path.startswith('/number'):
            response_body = str(TinyHandler.the_number)

        if self.path.startswith('/indices'):
            response_body = '[0][ ]1st  [1][ ]2nd  [2][ ]3rd\n\n[3][ ]4th  [4][ ]5th  [5][ ]6th\n\n[6][ ]7th  [7][ ]8th  [8][ ]9th'

        # E.g., /1/12345
        s = re_search('^/[123]/?.*?(\d{1,5})$', self.path)
        if s is not None:
            number = TinyHandler.normalize(s.group(1))
            if number == TinyHandler.the_number:
                response_body = '{} was correct!'.format(number)
            else:
                response_body = 'Try again!'
            TinyHandler.the_number = randint(1, 99999)
            response_body += '\nNew number: {}'.format(TinyHandler.the_number)

        if self.path.startswith('/echo/'):
            response_body = self.path.replace('/echo/', '')
            response_body = unquote(response_body)

        if self.path.startswith('/check'):
            number = 0
            s = re_search('number=(\d{1,5})', self.headers.get('cookie', ''))
            if s is not None and s.groups():
                number = TinyHandler.normalize(s.group(1))
            if not number:
                # Search again in the path/querystring.
                s = re_search('\d{1,5}', self.path)
                if s is not None:
                    number = TinyHandler.normalize(s.group(0))
            if number == TinyHandler.the_number:
                response_body = '{} was correct!'.format(number)
            else:
                response_body = 'Try again!'

        self.respond(response_body, headers)

    def do_POST(self):
        headers = {}
        response_body = 'Try again!'

        content_length = int(self.headers.get('content-length', 0))
        body = self.rfile.read(size=content_length)

        if self.path.startswith('/cookie'):
            number = 0
            # Accept both JSON and url-encoded form data.
            try:
                number = TinyHandler.normalize(loads(body)['number'])
            except:
                s = re_search('number=(\d{1,5})', body)
                if s is not None and s.groups():
                    number = TinyHandler.normalize(s.group(1))
            if number == TinyHandler.the_number:
                headers['Set-Cookie'] = 'number={}'.format(TinyHandler.the_number)
                response_body = '"number" cookie set to {}!'.format(TinyHandler.the_number)

        if self.path.startswith('/number'):
            s = re_search('number=(\d{1,5})', self.headers.get('cookie', ''))
            number_cookie = 0
            if s is not None and s.groups():
                number_cookie = int(s.group(1))
            if number_cookie == TinyHandler.the_number:
                number = randint(1, 99999)
                # Accept both JSON and url-encoded form data.
                try:
                    number = TinyHandler.normalize(loads(body)['number'])
                except:
                    s = re_search('number=(\d{1,5})', body)
                    if s is not None and s.groups():
                        number = TinyHandler.normalize(s.group(1))
                TinyHandler.the_number = number
                response_body = 'Number set to {}!'.format(TinyHandler.the_number)

        self.respond(response_body, headers)

    def respond(self, response_body, headers=dict()):
        self.send_response(200, 'OK')
        self.send_header('Content-Length', len(response_body))
        for h, v in headers.items():
            self.send_header(h, v)
        self.end_headers()
        self.wfile.write(response_body)

