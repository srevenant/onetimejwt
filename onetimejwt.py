# vim:set et ts=4 sw=4 ai ft=python:
# pylint: disable=superfluous-parens

"""
One Time JWT

Simple mechanism for cross service authorization.  Usage:

Client side:

    import onetimejwt

    jwt = onetimejwt.generate('shared secret', 60) # shared secret, 60 second age

    headers = {
        "Authorization": "Bearer " + onetimejwt.generate('shared secret', 60)
    }

Server side, create a single instance of Manager and use it for all threads:

    import onetimejwt

    # at startup, creates a cleanup thread
    # note: you can include any number of secrets
    JTM = onetimejwt.Manager('shared secret', maxage=60)

    JTM.housekeeper()

    # during processing -- throws JwtFailed exception if not authorized
    JTM.valid(headers.get('Authorization'))

Manager will keep a list of recognized JWTS, and uses logging of a warning level
to report problems.

------------------------------------------------------------------

Copyright 2016 Brandon Gillespie

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""

import threading
import uuid
import time
import jwt
import timeinterval # look elsewhere for this module

__version__ = 1.0

def generate(secret, age):
    """Generate a one-time jwt with an age in seconds"""
    jti = str(uuid.uuid1()) # random id
    return jwt.encode({'exp':int(time.time() + age), 'jti':jti}, secret)

def mutex(func):
    """use a thread lock on current method, if self.lock is defined"""
    def wrapper(*args, **kwargs):
        """Decorator Wrapper"""
        lock = args[0].lock
        lock.acquire(True)
        try:
            return func(*args, **kwargs)
        except:
            raise
        finally:
            lock.release()

    return wrapper

class JwtFailed(Exception):
    """Exception"""
    pass

class Manager(object):
    """
    Threadsafe mechanism to have one-time jwts.

    """

    secrets = []
    jwts = {}
    age = 60
    lock = threading.Lock()

    def __init__(self, *secrets, **kwargs):
        self.age = kwargs.get('age', 60)
        self.secrets = list(secrets)
        timeinterval.start(self.age * 1000, self._clean)

    @mutex
    def _clean(self):
        """Run by housekeeper thread"""
        now = time.time()
        for j in self.jwts:
            if (now - self.jwts[j]) > (self.age*2):
                del self.jwts[j]

    @mutex
    def already_used(self, tok):
        """has this jwt been used?"""
        if tok in self.jwts:
            return True
        self.jwts[tok] = time.time()
        return False

    def valid(self, token):
        """is this token valid?"""
        now = time.time()

        if 'Bearer ' in token:
            token = token[7:]

        for secret in self.secrets:
            try:
                data = jwt.decode(token, secret)
                break
            except jwt.DecodeError:
                continue
            except jwt.ExpiredSignatureError:
                raise JwtFailed("Jwt expired")

        if not data:
            raise JwtFailed("Jwt cannot be decoded")

        exp = data.get('exp')
        if not exp:
            raise JwtFailed("Jwt missing expiration (exp)")

        if now - exp > self.age:
            raise JwtFailed("Jwt bad expiration - greater than I want to accept")

        jti = data.get('jti')
        if not jti:
            raise JwtFailed("Jwt missing one-time id (jti)")

        if self.already_used(jti):
            raise JwtFailed("Jwt re-use disallowed (jti={})".format(jti))

        return True


