from datetime import datetime, timezone, timedelta
import jwt

_email = 'hey'
_password = 'hi'

TEST_SECRET_KEY = 'DEV_SEC'
token = jwt.encode({'email': _email, 'exp': datetime.utcnow() + timedelta(minutes=30)}, TEST_SECRET_KEY, algorithm="HS256")
print(token)

data = jwt.decode(token, TEST_SECRET_KEY, algorithms=["HS256"])

print(data)