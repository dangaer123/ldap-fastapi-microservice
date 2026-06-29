from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPBindError

app = FastAPI(title="LDAP Auth & Profile API")

LDAP_SERVER_URL = "ldap://127.0.0.1:389"
LDAP_BASE_DN = "dc=company,dc=local"
# Служебный пользователь
LDAP_SEARCH_USER_DN = "cn=api_reader,dc=company,dc=local"
LDAP_SEARCH_USER_PASSWORD = "readerpassword"

# Шаблон входных данных для аутентификации
class LoginSchema(BaseModel):
    username: str
    password: str

# Класс для ошибки в случае отсутствия запрашиваемого пользователя в БД
class UserNotFoundError(Exception):
    """Вызывается, если пользователя нет в дереве LDAP"""
    pass

# Извлечение доступных атрибутов класса inetOrgPerson с LDAP-сервера
def fetch_allowed_attributes() -> list[str]:
    server = Server(LDAP_SERVER_URL, get_info=ALL)
    try:
        conn = Connection(server, user=LDAP_SEARCH_USER_DN, password=LDAP_SEARCH_USER_PASSWORD, auto_bind=True)
        server.get_info_from_server(conn)
        schema = server.schema

        all_attrs = set()
        target_classes = ['inetOrgPerson']

        while target_classes:
            current_class_name = target_classes.pop(0)
            obj_class = schema.object_classes.get(current_class_name)

            if obj_class:
                all_attrs.update(obj_class.must_contain)
                all_attrs.update(obj_class.may_contain)

                if obj_class.superior:
                    target_classes.extend(obj_class.superior)

        if not all_attrs:
            return ["uid", "mail", "mobile", "cn", "sn"]

        return sorted(list(all_attrs))

    except LDAPException:
        return ["uid", "mail", "mobile", "cn", "sn"]

# Вспомогательная функция для поиска пользователя по uid
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

# Функция для аутентификации пользователя
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

# Эндпоинт для получения доступных атрибутов
@app.get("/attributes", summary="Получить динамический список полей с сервера")
def get_available_attributes():
    attrs = fetch_allowed_attributes()
    return {
        "status": "success",
        "available_attributes": attrs
    }

# Функция для получения данных о пользователе по выбранному атрибуту
@app.get("/users/", summary="Динамический поиск профиля")
def search_user_profile(
        attr: str = Query(..., description="Поле для поиска (сверьтесь с /attributes)"),
        value: str = Query(..., description="Значение для поиска")
):
    allowed_attributes = fetch_allowed_attributes()
    if attr not in allowed_attributes:
        raise HTTPException(
            status_code=400,
            detail=f"Атрибут '{attr}' не поддерживается сервером для поиска."
        )

    server = Server(LDAP_SERVER_URL, get_info=ALL)
    try:
        conn = Connection(server, user=LDAP_SEARCH_USER_DN, password=LDAP_SEARCH_USER_PASSWORD, auto_bind=True)
        search_filter = f"({attr}={value})"

        conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=allowed_attributes
        )

        if not conn.entries:
            raise HTTPException(status_code=404, detail=f"Пользователь с {attr}='{value}' не найден")

        entry = conn.entries[0]

        profile_data = {"dn": entry.entry_dn}
        for field in allowed_attributes:
            if field in entry:
                profile_data[field] = entry[field].value

        return {
            "status": "success",
            "data": profile_data
        }

    except LDAPBindError:
        raise HTTPException(status_code=500, detail="Ошибка конфигурации служебного аккаунта")
    except LDAPException:
        raise HTTPException(status_code=500, detail="LDAP-сервер недоступен")