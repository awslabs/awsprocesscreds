import base64


def create_assertion(roles):
    saml_assertion = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">'
        '<saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">'
    )
    for role in roles:
        partial = '<saml2:AttributeValue>%s</saml2:AttributeValue>' % role
        saml_assertion += partial
    saml_assertion += (
        '</saml2:Attribute>'
        '</saml2:Assertion>'
        '</saml2p:Response>'
    )
    return base64.b64encode(saml_assertion.encode('ascii'))