# POC aquao-authentication-jwt-php-symfony

[![aquao-poc-node](data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIzMTEuNzk5OTk5MjM3MDYwNTUiIGhlaWdodD0iMzUiIHZpZXdCb3g9IjAgMCAzMTEuNzk5OTk5MjM3MDYwNTUgMzUiPjxyZWN0IHdpZHRoPSI2NC4zNDk5OTg0NzQxMjExIiBoZWlnaHQ9IjM1IiBmaWxsPSIjMzFDNEYzIi8+PHJlY3QgeD0iNjQuMzQ5OTk4NDc0MTIxMSIgd2lkdGg9IjE5MiIgaGVpZ2h0PSIzNSIgZmlsbD0iIzM4OUFENSIvPjx0ZXh0IHg9IjMyLjE3NDk5OTIzNzA2MDU1IiB5PSIxNy41IiBmb250LXNpemU9IjEyIiBmb250LWZhbWlseT0iJ1JvYm90bycsIHNhbnMtc2VyaWYiIGZpbGw9IiNGRkZGRkYiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGFsaWdubWVudC1iYXNlbGluZT0ibWlkZGxlIiBsZXR0ZXItc3BhY2luZz0iMiI+QVFVQU88L3RleHQ+PHRleHQgeD0iMTYwLjM0OTk5ODQ3NDEyMTEiIHk9IjE3LjUiIGZvbnQtc2l6ZT0iMTIiIGZvbnQtZmFtaWx5PSInTW9udHNlcnJhdCcsIHNhbnMtc2VyaWYiIGZpbGw9IiNGRkZGRkYiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtd2VpZ2h0PSI5MDAiIGFsaWdubWVudC1iYXNlbGluZT0ibWlkZGxlIiBsZXR0ZXItc3BhY2luZz0iMiI+UFJPT0YgT0YgQ09OQ0VQVDwvdGV4dD48cmVjdCB4PSIyNTYuMzQ5OTk4NDc0MTIxMSIgd2lkdGg9IjU1LjQ1MDAwMDc2MjkzOTQ1IiBoZWlnaHQ9IjM1IiBmaWxsPSIjMjY3NEE0Ii8+PHRleHQgeD0iMjg0LjA3NDk5ODg1NTU5MDgiIHk9IjE3LjUiIGZvbnQtc2l6ZT0iMTIiIGZvbnQtZmFtaWx5PSInUm9ib3RvJywgc2Fucy1zZXJpZiIgZmlsbD0iI0ZGRkZGRiIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC13ZWlnaHQ9IjUwMCIgYWxpZ25tZW50LWJhc2VsaW5lPSJtaWRkbGUiIGxldHRlci1zcGFjaW5nPSIyIj5OT0RFPC90ZXh0Pjwvc3ZnPg==)](https://aquao.fr)

This a PHP/Symfony  Proof Of Concept to demonstrate how to authenticate against Rbe rest services with jwt token
## How to start

Edit .env file and replace %**% with the correct values

* HOST
* JWT_ISSUER
* JWT_SUBJECT
* JWT_KEY
* SESSION_NAME

### Prerequisites

You should have composer 2.7+ with php 8+

### Install

Run `composer install`

## Start

Run `symfony server:start --port=3000`

## Proceed

In your browser, go to `http://localhost:3000`

## Authors

AquaO - support@aquao.fr

## License

BSD Zero Clause License
Copyright (C) 2023 by AquaO support@aquao.fr

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL,
DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE
OR PERFORMANCE OF THIS SOFTWARE.