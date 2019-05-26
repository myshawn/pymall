#!/usr/bin/python3
from flask import json
from flask import request
from flask import Flask, url_for
import urllib
import urllib.request 
import base64
from Crypto.Cipher import AES
import Crypto.Cipher.AES

app = Flask(__name__)
app_id = 'wx12bae3d0d8c0bd1d';
secret_key = 'b43f61f0affae5a8af4d38214e3e28d4';

def wx_code2session_url(_app_id, _secret_key, _code):
    return 'https://api.weixin.qq.com/sns/jscode2session?appid=' + _app_id + '&secret=' + _secret_key + '&js_code=' + _code + '&grant_type=authorization_code'

@app.route('/')
def api_root():
    return 'Welcome'

@app.route('/articles')
def api_articles():
    return 'List of ' + url_for('api_articles')

@app.route('/articles/<articleid>')
def api_article(articleid):
    return 'You are reading ' + articleid

@app.route('/json')
def do_json():
    hello = {"name":"stranger", "say":"hello"}
    return json.dumps(hello)

@app.route('/mini/get_openid', methods = ['POST'])
def mini_get_openid():
    if request.headers['Content-Type'] == 'application/x-www-form-urlencoded':
        encryptedData = request.form['encryptedData']
        iv = request.form['iv']
        code = request.form['code']
        if encryptedData == None or iv == None or code == None:
            return '', 400

        print("encryptedData: " + encryptedData + ", iv: " + iv + ", code: " + code)

        req = urllib.request.urlopen(wx_code2session_url(app_id, secret_key, code))
        json_res = json.load(req)
        print("session_key: " + json_res['session_key'] + ", openid: " + json_res['openid'])
        return json.dumps(json_res)
    return '', 400

@app.route('/mini/get_id', methods = ['POST'])
def mini_get_id():
    if request.headers['Content-Type'] == 'application/x-www-form-urlencoded':
        encryptedData = request.form['encryptedData']
        iv = request.form['iv']
        code = request.form['code']
        if encryptedData == None or iv == None or code == None:
            return '', 400

        print("encryptedData: " + encryptedData + ", iv: " + iv + ", code: " + code)
                
        aesCipher = base64.b64decode(encryptedData)
        aesIV = base64.b64decode(iv)
        
        req = urllib.request.urlopen(wx_code2session_url(app_id, secret_key, code))
        json_res = json.load(req)
        print("session_key: " + json_res['session_key'] + ", openid: " + json_res['openid'])
        aesKey = base64.b64decode(json_res['session_key'])
        
        decipher = AES.new(aesKey, AES.MODE_CBC, aesIV)
        plaintext = decipher.decrypt(aesCipher)

        print(plaintext[-2])
        print(plaintext[-1])
        #strText = bytes.decode(plaintext)
        #strText = strText[0:-2]
        #json_text = json.loads(strText)
        #return json.dumps(json_text)
        return plaintext[0:-2]
    return '', 400

if __name__ == '__main__':
    app.run(debug=True)

