# LDAP Authentication & Profile API

Веб-сервис на FastAPI для авторизации пользователей и получения их профилей из Docker-контейнера OpenLDAP.

## Технологии
* Python 3.12+
* FastAPI
* ldap3 (библиотека для работы с LDAP)

## Как запустить локально
1. Клонировать репозиторий
2. Поднять LDAP-сервер в Docker (или указать свой URL)
3. Запустить проект: `uvicorn main:app --reload`