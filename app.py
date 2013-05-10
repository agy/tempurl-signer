#!/usr/bin/env python
# Copyright 2013 Samuel Merritt <spam@andcheese.org>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from flask import Flask, request, abort
import hashlib
import hmac
import time


def get_tempurl_secret():
    # You'll probably want to do something smart here
    return "correcthorsebatterystaple"


def get_swift_account():
    # You'll probably want to do something smart here
    return "AUTH_test"


def is_authorized(request):
    # You'll probably want to do something smart here
    return True


def sign(method, expires, container_name, object_name):
    url = "/v1/{acc}/{con}/{obj}".format(
        acc=get_swift_account(),
        con=container_name,
        obj=object_name)
    sig = hmac.new(
        get_tempurl_secret(),
        "\n".join([method, str(expires), url]),
        hashlib.sha1).hexdigest()
    return url + "?temp_url=sig={sig}&temp_url_expires={exp}".format(
        sig=sig,
        exp=expires)


app = Flask(__name__)


@app.route("/")
def sign_urls():
    if not is_authorized(request):
        abort(403)
    try:
        segments = int(request.args.get('segments', '1'))
        duration = int(request.args.get('duration', 3600))
        hostname = request.args['hostname']
        if '/' in hostname:
            raise ValueError("no slashes in hostnames")
        if segments <= 0:
            raise ValueError("segments must be positive")
        if duration <= 0 or duration > 86400:
            raise ValueError("duration negative or more than a day")
    except (ValueError, KeyError) as e:
        abort(400, e.message)

    container = "backups_" + hostname
    now = time.time()
    base_object = str(now)
    expires = now + duration
    urls = [sign('PUT', duration, container, "%s_%d" % (base_object, i))
            for i in xrange(segments)]
    return "\n".join(urls)


if __name__ == '__main__':
    app.run()
