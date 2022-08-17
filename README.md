How to use:\
Script init.ps1 creates private key and self-signed certificate. After that init.ps1 stores key and certificate into pfx.pfx file \
Script main.ps1 is a simple web server that listens for requests and sends emails with tokens. \
send http request:\
your ip (i.e. localhost or 127.0.0.1)/token=aaa&email=bbb&timestamp=ccc. timestamp should be presented in seconds \
http://127.0.0.1/?token=aaa&email=bbb@aaa.com&timestamp=123



Config\
{\
    "email":"your email here",\
    "password":"email pass",\
    "SmtpServer":"smtp server",\
    "pfxPass":"pfx password",\
    "applicationToken":"app token",\
    "urlBinding":"your url here"\
}
