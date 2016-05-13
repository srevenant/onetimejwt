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
