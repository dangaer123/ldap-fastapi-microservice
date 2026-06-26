from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPBindError

app = FastAPI(title="LDAP Auth & Profile API")

LDAP_SERVER_URL = "ldap://127.0.0.1:389"
LDAP_BASE_DN = "dc=company,dc=local"

LDAP_SEARCH_USER_DN = "cn=api_reader,dc=company,dc=local"
LDAP_SEARCH_USER_PASSWORD = "readerpassword"


class LoginSchema(BaseModel):
    username: str
    password: str

class UserNotFoundError(Exception):
    """Вызывается, если пользователя нет в дереве LDAP"""
    pass


def find_user_dn(username: str) -> str:
    server = Server(LDAP_SERVER_URL, get_info=ALL)

    try:
        conn = Connection(server, user=LDAP_SEARCH_USER_DN, password=LDAP_SEARCH_USER_PASSWORD, auto_bind=True)
        search_filter = f"(uid={username})"
        conn.search(search_base=LDAP_BASE_DN, search_filter=search_filter, search_scope=SUBTREE)

        if not conn.entries:
            raise UserNotFoundError()

        return conn.entries[0].entry_dn

    except LDAPException:
        raise


@app.post("/auth")
def authenticate_user(payload: LoginSchema):
    server = Server(LDAP_SERVER_URL, get_info=ALL)

    try:
        user_dn = find_user_dn(payload.username)
        conn = Connection(server, user=user_dn, password=payload.password, auto_bind=True)
        return {"status": "success", "message": "Авторизация успешна!"}
    
    except LDAPBindError:
        # логин верный, но пароль неверный
        raise HTTPException(
            status_code=401,
            detail="Ошибка авторизации: неверный логин или пароль"
        )
    except LDAPException:
        # ошибка самого сервера
        raise HTTPException(
            status_code=500,
            detail="Внутренняя ошибка: LDAP-сервер недоступен"
        )
    except UserNotFoundError:
        # не нашли логин
        raise HTTPException(
            status_code=401,
            detail="Ошибка авторизации: неверный логин или пароль"
        )


@app.get("/users/{username}")
def get_user_profile(username: str):
    server = Server(LDAP_SERVER_URL, get_info=ALL)

    try:
        conn = Connection(server, user=LDAP_SEARCH_USER_DN, password=LDAP_SEARCH_USER_PASSWORD, auto_bind=True)

        search_filter = f"(uid={username})"

        conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=['cn', 'sn', 'mail', 'mobile', 'uid']
        )

        if not conn.entries:
            raise HTTPException(status_code=404, detail=f"Пользователь '{username}' не найден")

        entry = conn.entries[0]

        profile_data = {
            "dn": entry.entry_dn,
            "name": entry.cn.value if 'cn' in entry else None,
            "surname": entry.sn.value if 'sn' in entry else None,
            "email": entry.mail.value if 'mail' in entry else None,
            "phone": entry.mobile.value if 'mobile' in entry else None,
            "uid": entry.uid.value if 'uid' in entry else None
        }

        return {
            "status": "success",
            "data": profile_data
        }

    except LDAPBindError:
        raise HTTPException(status_code=500, detail="Ошибка конфигурации служебного аккаунта")
    except LDAPException:
        raise HTTPException(status_code=500, detail="LDAP-сервер недоступен")