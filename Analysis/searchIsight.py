# -*- coding: utf-8 -*-
import hashlib
import hmac
import email
import json
import requests


class APIRequestHandler(object):
    def __init__(self):
        self.URL = 'https://api.isightpartners.com'
        self.public_key = '6dc730230d54fb2c67cd20eddc88b45d69366d05bf57abba1990549df6656f1d'
        self.private_key = '691640c154e3e42a51332ce678135a6dd2b76431b7904ec9b131f8bc271972dc'
        self.accept_version = '2.5'

    def run(self):
        time_stamp = email.utils.formatdate(localtime=True)
        ENDPOINT = '/pivot/indicator/ip/89.249.67.22'
        accept_header = 'application/json'
        new_data = ENDPOINT + self.accept_version + accept_header + time_stamp
        print(new_data)

        key = bytearray()
        key.extend(map(ord, self.private_key))
        hashed = hmac.new(key, new_data.encode('utf-8'), hashlib.sha256)

        headers = {
            'Accept': accept_header,
            'Accept-Version': self.accept_version,
            'X-Auth': self.public_key,
            'X-Auth-Hash': hashed.hexdigest(),
            'Date': time_stamp,
        }

        r = requests.get(self.URL + ENDPOINT, headers=headers)
        status_code = r.status_code
        # print('status_code = ' + str(status_code))

        if status_code == 200:
            json_data = json.loads(r.text)
            length = len(json_data['message']['publishedIndicators'])
            for c in range(0, length):
                actor = []
                actor = json_data['message']['publishedIndicators'][c]['actor']
            if actor:
                print(actor)
            # print(r.text)
            # f = open('response.json', 'w')
            # f.write(r.text)
            # f.close()
        else:
            print(r.content)


if __name__ == '__main__':
    request_handler = APIRequestHandler()
    request_handler.run()
