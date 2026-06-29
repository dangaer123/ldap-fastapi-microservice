# LDAP Authentication & Profile API

Веб-сервис на FastAPI для авторизации пользователей и получения их профилей из Docker-контейнера OpenLDAP.

## Технологии
* Python 3.12+
* FastAPI
* ldap3 (библиотека для работы с LDAP)

## Как запустить локально
1. Клонировать репозиторий
2. Поднять LDAP-сервер в Docker
3. Создать несколько пользователей в phpldapadmin (по умолчанию `127.0.0.1:8081`, логин -cn=admin,dc=company,dc=local, пароль - adminpassword)
4. Запустить проект main.py: `uvicorn main:app --reload`

## Краткая инструкция
Есть три эндпоинта:
1. `/auth` - POST-запрос для аутентификации пользователя. Тело запроса выглядит так: `{
    "username": "string",
    "password": "string"
}`
2. `/attributes`: - GET-запрос для получения списка доступных атрибутов, которые используются в следующем запросе
3. `/users` - Основной GET-запрос, получает на вход query-параметры (например, `/users/?attr=mail&value=user@mail.com`) и возвращает все доступные атрибуты о пользователе в виде `{
  "status": "success",
  "data": {
    "dn": "uid=user,ou=users,dc=company,dc=local",
    "audio": null,
    "businessCategory": null, 
    "carLicense": null,
    "cn": "Elon",
    "departmentNumber": null, ...}`