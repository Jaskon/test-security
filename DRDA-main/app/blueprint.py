from flask import Flask

app = Flask('OX Security - Secrets are out there')
app.config['SECRET_KEY'] = '123aa8a93bdde342c871564a62282af857bda14b3359fde95d0c5e4b321610c1'

# TODO: move hard-coded secrets to a vault
{
  'ANACONDA': 'bo-dbdd0c5d-bc55-4263-9d60-2f70abe4b162',
  'PYPI': 'pypi-AgEIcHlwaS5vcmcCJGJmZmMzOTE2LTOXYzctNGQ4My04NWUxLTA1YjI1NTZkYjgyYQACNnsicGVyOXlzc2lvbnMiOiB7InByb2plY3RzIjogWyJib2tlaCJdfSwgInZlcnwpb24iOiAxfQAABiBNo6M5tOXTEF50ZO2Sktgk1etIb_VilUoDsT_4cIkOBA',
  'NPM': '6d621222-b0c3-470a-b929-0145bb40911b',
  'AWS': ('AKIAYF7OXAZCOSSGRVNM', 'uH5o2qUFX+JD67C5qxZt0e3TUrcRmNPCJ5y2MEQ5')
}

solved_captcha = solver.recaptcha(
            sitekey="6Lc-wnQjAAAAADa5SPd68d0O3xmj0030uaVzpnXP",
            url="https://auth0.openai.com/u/login/identifier",
        )

api_key = 'sk-U7tcdykcOkKjEwlOXBdMT3BlbkwJTA6ks1EpI5bInU1IRpih'

my_api_key = "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"

captcha_key = "ed3a08532982a6d4db4abbea4433c60e"
twocaptcha_some_key = "ed3a08532982a6d4db4abbea4433c60e"

app.register_blueprint(mod_hello, url_prefix='/hello')
app.register_blueprint(mod_user, url_prefix='/user')
app.register_blueprint(mod_posts, url_prefix='/posts')
app.register_blueprint(mod_mfa, url_prefix='/mfa')
app.register_blueprint(mod_csp, url_prefix='/csp')
app.register_blueprint(mod_api, url_prefix='/api')

app.secret_key = 'd5fb8c4fa8bd46638dadc4e751e0d68d'
