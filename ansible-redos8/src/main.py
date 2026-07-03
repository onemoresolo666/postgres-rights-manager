# =========================================================================
# СТРОКИ 1-3: ЖЁСТКИЙ DevOps-ИНЖЕКТ ПУТЕЙ
# =========================================================================
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# -------------------------------------------------------------------------
# ВАШИ ОРИГИНАЛЬНЫЕ ИМПОРТЫ СО СКРИНШОТА (ОСТАВИТЬ БЕЗ ИЗМЕНЕНИЙ)
# -------------------------------------------------------------------------
import jwt
import datetime
import asyncio
import logging
from utils import get_current_user, RoleChecker
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, Depends, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from bcrypt import hashpw, gensalt, checkpw
from psycopg import connect, sql
from psycopg.rows import dict_row
from contextlib import asynccontextmanager

# Импортируем модули проекта
import utils
import users
import panel_users
import smtp



@asynccontextmanager
async def lifespan(app: FastAPI):
    # ================================================================= #
    # 1. СЕКЦИЯ СТАРТА ПРИЛОЖЕНИЯ                                       #
    # ================================================================= #
    logger.info("=== [ОТЛАДКА ИБ-КОНТУРА] СТАРТ ПРОВЕРКИ АДМИНИСТРАТОРА ===")
    
    # Инициализируем пул подключений к PostgreSQL 18
    utils.init_pool()
    
    try:
        with utils.db_pool.connection() as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # Проверяем, заведен ли дефолтный admin в базе проекта
                cur.execute("SELECT 1 FROM public.panel_users WHERE username = 'admin';")
                admin_exists = cur.fetchone()
                
                if not admin_exists:
                    logger.info("[ОТЛАДКА] Администратор не найден в СУБД. Генерируем хэш...")
                    hashed = hashpw("admin123".encode(), gensalt()).decode()
                    
                    logger.info("[ОТЛАДКА] Отправляем команду INSERT в service_manager_db...")
                    cur.execute(
                        """
                        INSERT INTO public.panel_users (username, password_hash, is_active, role) 
                        VALUES ('admin', %s, true, 'admin');
                        """,
                        (hashed,)
                    )
                    logger.info("=== [ОТЛАДКА] АДМИНИСТРАТОР УСПЕШНО СОЗДАН! ===")
                else:
                    logger.info("[ОТЛАДКА] Пользователь 'admin' уже существует. Пропускаем вставку.")
    except Exception as e:
        logger.error(f"!!! [КРИТИЧЕСКАЯ ОШИБКА ИНИЦИАЛИЗАЦИИ БАЗЫ]: {str(e)}", exc_info=True)

    # Запускаем штатную фоновую задачу очистки сгоревших токенов
    bg_task = asyncio.create_task(users.token_garbage_collector())
    
    yield  # <-- ТОЧКА РАЗДЕЛЕНИЯ СТАРТА И СТОПА (Управление передается роутерам)

    # ================================================================= #
    # 2. СЕКЦИЯ ОСТАНОВКИ ПРИЛОЖЕНИЯ                                    #
    # ================================================================= #
    logger.info("[ОТЛАДКА] Служба останавливается. Корректно закрываем ресурсы...")
    bg_task.cancel()
    utils.close_pool()


# Инициализация самого приложения (lifespan подключен идеально)
app = FastAPI(
    title="Secure PostgreSQL Rights Manager API",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Настройка логгера (перенесли в самый низ, под объявление объекта app)
logger = logging.getLogger("uvicorn.error")



# Настройка CORS контура
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Подключаем изолированные роутеры
app.include_router(users.router)
app.include_router(panel_users.router)
app.include_router(smtp.router)

# Схемы строгой валидации Pydantic v2
class ServerRegistrationRequest(BaseModel):
    server_id: str = Field(..., min_length=1, max_length=50, pattern="^[a-zA-Z0-9_]+$")
    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(5432, ge=1, le=65535)
    db_user: str = Field(..., min_length=1, max_length=63)
    dbname: str = Field(..., min_length=1, max_length=63)
    password: str = Field(..., min_length=1)

class PrivilegeManagerRequest(BaseModel):
    target_server: str
    target_db: str
    username: str
    scope: str  # DATABASE, SCHEMA, TABLE, SEQUENCE
    schema_name: str = "public"
    table_name: str = None
    action: str  # GRANT или REVOKE
    privilege: str  # CONNECT, USAGE, SELECT, etc.

class SystemRoleManagerRequest(BaseModel):
    target_server: str
    username: str
    system_role: str
    action: str  # GRANT или REVOKE

class LoginRequest(BaseModel):
    username: str
    password: str



# =========================================================================
# # 0. КОНТУР АВТОРИЗАЦИИ И ГЕНЕРАЦИИ СЕССИОННЫХ JWT ТОКЕНОВ
# =========================================================================
@app.post("/api/login")
@app.post("/api/login/")
def login(req: LoginRequest):
    # Логируем саму попытку входа до начала проверок безопасности
    logger.info(f"[ИБ-АВТОРИЗАЦИЯ] >>> Попытка входа в систему. Пользователь: '{req.username}'")

    if utils.db_pool is None:
        utils.init_pool()

    try:
        with utils.db_pool.connection() as conn:
            with conn.cursor() as cur:
                # Четко запрашиваем только необходимые для валидации поля
                cur.execute(
                    "SELECT password_hash, is_active, role FROM panel_users WHERE username = %s;",
                    (req.username,)
                )
                row = cur.fetchone()

                # # 1. [ИБ-ФИКС]: ПРИНУДИТЕЛЬНЫЙ ПЕРЕНОС ПРОВЕРКИ БЛОКИРОВКИ НА САМЫЙ ВВЕРХ
                # row[1] — это флаг активности аккаунта (is_active: boolean)
                if row and not row[1]:
                    logger.warning(f"[ИБ-АУДИТ] !!! ЗАБЛОКИРОВАННЫЙ ВХОД | Попытка авторизации в забаненный аккаунт: '{req.username}'")
                    raise HTTPException(
                        status_code=403, 
                        detail="Ваша учетная запись заблокирована. Обратитесь к старшему DBA."
                    )

                # # 2. ПРОВЕРКА СУЩЕСТВОВАНИЯ ПОЛЬЗОВАТЕЛЯ И ВАЛИДНОСТИ КРИПТОГРАФИЧЕСКОГО ХЭША
                # Защита от Time-based атак: чекаем пароль только если row существует, иначе имитируем проверку
                is_valid_password = False
                if row and row[0]:
                    try:
                        is_valid_password = checkpw(req.password.encode(), row[0].encode())
                    except Exception:
                        is_valid_password = False

                if not row or not is_valid_password:
                    # КРИТИЧНО ДЛЯ ИБ: фиксируем факт неверного ввода пароля/логина
                    logger.warning(f"[ИБ-АУДИТ] !!! ОТКАЗ В ДОСТУПЕ | Неверное имя пользователя или пароль. Логин: '{req.username}'")
                    raise HTTPException(
                        status_code=401, 
                        detail="Неверное имя пользователя или пароль"
                    )

                # Извлекаем роль с гарантированным фолбеком, исключая падение на NULL/None
                db_role = row[2]
                user_role = str(db_role).strip() if db_role else "admin"

                # # 3. ГЕНЕРАЦИЯ СЕССИОННОГО JWT ТОКЕНА (СОВРЕМЕННЫЙ СТАНДАРТ PYTHON 3.12+)
                # Используем timezone-aware объект UTC вместо устаревшего utcnow()
                now = datetime.datetime.now(datetime.timezone.utc)
                expiration = now + datetime.timedelta(minutes=60)

                token_data = {
                    "sub": req.username,
                    "role": user_role,
                    "exp": int(expiration.timestamp())  # Передаем UNIX-timestamp для кроссплатформенной валидации
                }

                token = jwt.encode(token_data, utils.JWT_SECRET, algorithm=utils.JWT_ALGORITHM)

                # КРИТИЧНО ДЛЯ ИБ: Фиксируем УСПЕШНЫЙ вход в панель с указанием роли
                logger.info(f"[ИБ-АУДИТ] <<< УСПЕХ АВТОРИЗАЦИИ | Пользователь '{req.username}' успешно авторизован. Роль: [{user_role}]")
                
                return {
                    "status": "success", 
                    "access_token": token, 
                    "token_type": "bearer", 
                    "role": user_role
                }

    except HTTPException:
        # Пробрасываем легитимные ИБ-отказы (401, 403) без изменений на фронтенд
        raise
    except Exception as e:
        # Логируем непредвиденный крах сервера авторизации с полным стеком ошибки
        logger.error(f"[ИБ-КРАХ] Ошибка сервера авторизации для пользователя '{req.username}': {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500, 
            detail="Ошибка сервера авторизации. Повторите запрос позже."
        )



# =========================================================================
# # 1. ПОЛУЧЕНИЕ СПИСКА СЕРВЕРОВ
# =========================================================================
@app.get("/api/servers")
@app.get("/api/servers/")
def get_servers_registry(current_user: str = Depends(utils.get_current_user)):
    # Логируем факт чтения чувствительной ИТ-инфраструктуры конкретным пользователем
    logger.info(f"[ИБ-АУДИТ] >>> Запрос реестра серверов. Пользователь: '{current_user}'")

    if utils.db_pool is None:
        utils.init_pool()

    try:
        with utils.db_pool.connection() as conn:
            with conn.cursor() as cur:
                # Наш strict-запрос, отсекающий заархивированные сервера
                cur.execute("SELECT server_id, host, port, db_user, dbname FROM registered_servers WHERE is_active = true ORDER BY server_id ASC;")
                rows = cur.fetchall()

                servers_list = []
                for r in rows:
                    # Безопасное приведение порта к int без риска падения рантайма
                    safe_port = 5432
                    if r[2] is not None:
                        try:
                            safe_port = int(str(r[2]).strip())
                        except (ValueError, TypeError):
                            safe_port = 5432

                    # ИБ-ФИКС: Математически точная расстановка индексов SELECT-запроса
                    servers_list.append({
                        "server_id": r[0],  # id
                        "host": r[1],       # host
                        "port": safe_port,  # port (обработанный r[2])
                        "db_user": r[3],    # db_user (четвертое поле)
                        "dbname": r[4]      # dbname (пятое поле)
                    })


                # Фиксируем успешную отдачу данных и количество найденных серверов
                logger.info(f"[ИБ-АУДИТ] <<< Реестр серверов успешно отдан пользователю '{current_user}'. Найдено инстансов: {len(servers_list)}")
                return {"status": "success", "servers": servers_list}

    except Exception as e:
        # КРИТИЧНО: Записываем крах подключения к базе в лог сервера РЕД ОС с полной трассировкой!
        logger.error(f"[ИБ-КРАХ] Ошибка чтения реестра серверов для пользователя '{current_user}': {str(e)}", exc_info=True)
        
        # Сохраняем вашу оригинальную структуру безопасного фолбэк-ответа для фронтенда
        return {"status": "error", "detail": f"Ошибка чтения реестра: {str(e)}", "servers": []}



# =========================================================================
# # 2. РЕГИСТРАЦИЯ НОВОГО СЕРВЕРА
# =========================================================================
@app.post("/api/register-server")
@app.post("/api/register-server/")
def register_server(
    req: ServerRegistrationRequest,
    current_user: str = Depends(RoleChecker(["admin"]))
):
    # # ИБ-ЛОГ: Фиксируем саму попытку добавления сервера в текстовом логе ОС РЕД ОС
    logger.info(f"[ИБ-АУДИТ] >>> Попытка регистрации узла СУБД. Администратор: '{current_user}', Сервер ID: '{req.server_id}', Хост: {req.host}")

    if utils.db_pool is None:
        utils.init_pool()

    try:
        # Криптографическое шифрование пароля до открытия транзакции (экономим ресурсы пула)
        encrypted_pw = utils.cipher.encrypt(req.password.encode()).decode()
    except Exception as cipher_err:
        logger.error(f"[ИБ-КРАХ] Ошибка шифрования пароля для сервера '{req.server_id}': {str(cipher_err)}")
        raise HTTPException(status_code=500, detail="Критическая ошибка криптографического модуля панели.")

    query = """
        INSERT INTO registered_servers (server_id, host, "port", db_user, dbname, encrypted_password, is_active)
        VALUES (%s, %s, %s, %s, %s, %s, true)
        ON CONFLICT (server_id)
        DO UPDATE SET
            host = EXCLUDED.host,
            "port" = EXCLUDED."port",
            db_user = EXCLUDED.db_user,
            dbname = EXCLUDED.dbname,
            encrypted_password = EXCLUDED.encrypted_password,
            is_active = true;
    """

    try:
        with utils.db_pool.connection() as conn:
            # Управляем транзакцией безопасно: если autocommit выключен, блок with сам сделает commit/rollback
            with conn.cursor() as cur:
                
                # Локальный перехват ошибок СУБД для предотвращения дедлоков рантайма
                try:
                    cur.execute(query, (req.server_id, req.host, req.port, req.db_user, req.dbname, encrypted_pw))
                except Exception as sql_err:
                    err_str = str(sql_err)
                    logger.error(f"[ИБ-ОТКАЗ] База данных отклонила регистрацию сервера {req.server_id}: {err_str}")
                    
                    # КРИТИЧНО ДЛЯ ИБ: Обязательно фиксируем СБОЙ операции во внутренний аудит-журнал!
                    utils.log_operation(
                        "PANEL_MANAGER",
                        str(current_user),
                        f"server.{req.server_id}",
                        "REGISTER_SERVER",
                        "INFRASTRUCTURE",
                        "error",
                        f"Ошибка СУБД при интеграции узла: {err_str}"
                    )
                    raise HTTPException(status_code=422, detail=f"Ошибка базы данных при регистрации узла: {err_str}")

                # Ваша штатная запись во внутреннюю таблицу audit_logs при УСПЕХЕ
                utils.log_operation(
                    "PANEL_MANAGER",
                    str(current_user),
                    f"server.{req.server_id}",
                    "REGISTER_SERVER",
                    "INFRASTRUCTURE",
                    "success",
                    f"Интегрирован узел кластера СУБД: {req.server_id}"
                )

                # # ИБ-ЛОГ: Подтверждаем успешное сохранение в системный журнал РЕД ОС
                logger.info(f"[ИБ-АУДИТ] <<< Узел СУБД '{req.server_id}' ({req.host}) успешно интегрирован администратором '{current_user}'.")
                return {"status": "success", "message": f"Сервер '{req.server_id}' успешно зарегистрирован и активирован в панели."}

    except HTTPException:
        # Пробрасываем контролируемые ошибки (422) на фронтенд
        raise
    except Exception as e:
        # Резервный верхнеуровневый перехват для сетевых крахов самого пула
        logger.error(f"[ИБ-КРАХ] Не удалось зарегистрировать сервер '{req.server_id}' пользователем '{current_user}': {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Ошибка добавления сервера (отказ пула соединений): {str(e)}")


# =========================================================================
# # 3. ДЕАКТИВАЦИЯ И АРХИВАЦИЯ СЕРВЕРА
# =========================================================================
@app.delete("/api/servers/{server_id}")
@app.delete("/api/servers/{server_id}/")
def delete_server(
    server_id: str,
    current_user: str = Depends(RoleChecker(["admin"]))
):
    # # ИБ-ЛОГ: Фиксируем саму попытку архивации узла СУБД в журнале ОС
    logger.info(f"[ИБ-АУДИТ] >>> Попытка деактивации сервера. Администратор: '{current_user}', Сервер ID: '{server_id}'")

    if utils.db_pool is None:
        utils.init_pool()

    query = """
        UPDATE registered_servers
        SET is_active = false
        WHERE server_id = %s AND is_active = true;
    """

    try:
        with utils.db_pool.connection() as conn:
            # Безопасное управление транзакцией: контекстный менеджер сам сделает commit/rollback
            with conn.cursor() as cur:
                
                # Локальный перехват ошибок СУБД для предотвращения дедлоков рантайма
                try:
                    cur.execute(query, (server_id,))
                except Exception as sql_err:
                    err_str = str(sql_err)
                    logger.error(f"[ИБ-ОТКАЗ] База данных отклонила архивацию сервера {server_id}: {err_str}")
                    
                    # КРИТИЧНО ДЛЯ ИБ: Обязательно фиксируем СБОЙ операции во внутренний аудит-журнал!
                    utils.log_operation(
                        "PANEL_MANAGER",
                        str(current_user),
                        f"server.{server_id}",
                        "ARCHIVE_SERVER",
                        "INFRASTRUCTURE",
                        "error",
                        f"Ошибка СУБД при деактивации узла: {err_str}"
                    )
                    raise HTTPException(status_code=422, detail=f"Ошибка базы данных при архивации узла: {err_str}")

                # Проверка: если ни одна строка не обновилась (сервер не найден или уже в архиве)
                if cur.rowcount == 0:
                    # # ИБ-ЛОГ: Предупреждение о том, что целевой узел не существует или уже в архиве
                    logger.warning(f"[ИБ-АУДИТ] !!! СБОЙ ДЕАКТИВАЦИИ | Сервер '{server_id}' не найден или уже заархивирован. Запрос от '{current_user}'")
                    raise HTTPException(status_code=404, detail="Сервер не найден или уже деактивирован.")

                # Запечатываем операцию в системном журнале логов панели (в СУБД) при УСПЕХЕ
                utils.log_operation(
                    "PANEL_MANAGER",
                    str(current_user),
                    f"server.{server_id}",
                    "ARCHIVE_SERVER",
                    "INFRASTRUCTURE",
                    "success"
                )

                # # ИБ-ЛОГ: Подтверждаем успешное выполнение операции
                logger.info(f"[ИБ-АУДИТ] <<< Сервер '{server_id}' успешно переведен в архив администратором '{current_user}'.")
                return {"status": "success", "message": f"Сервер '{server_id}' успешно деактивирован и отправлен в архив."}

    except HTTPException:
        # Пробрасываем контролируемые ошибки (404, 422) на фронтенд без изменений
        raise
    except Exception as e:
        # Резервный верхнеуровневый перехват для сетевых крахов самого пула
        logger.error(f"[ИБ-КРАХ] Ошибка транзакции или падение пула при деактивации сервера '{server_id}' администратором '{current_user}': {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Ошибка деактивации сервера (отказ пула соединений): {str(e)}")



# =========================================================================
# # 4. ТЕСТ ПОДКЛЮЧЕНИЯ ИЗ СТРОКИ ИЛИ ФОРМЫ
# =========================================================================
@app.post("/api/test-server-connection")
@app.post("/api/test-server-connection/")
def test_server_connection(
    req: ServerRegistrationRequest,
    current_user: str = Depends(RoleChecker(["admin"]))
):
    # # ИБ-ЛОГ: Фиксируем старт разведки линка с указанием целевого хоста и порта
    logger.info(f"[ИБ-АУДИТ] >>> Запрос проверки связи с СУБД. Администратор: '{current_user}', Хост: {req.host}:{req.port}, БД: {req.dbname}")

    target_password = req.password
    if target_password == "via_saved_credentials":
        try:
            server_config = utils.get_server_from_db(req.server_id)
            target_password = server_config.get("password", "")
        except Exception as cred_err:
            logger.warning(f"[ИБ-АУДИТ] !!! СБОЙ ИЗВЛЕЧЕНИЯ КРЕДЕНШЛОВ | Не удалось достать пароль для сервера '{req.server_id}'. Администратор: '{current_user}'. Ошибка: {str(cred_err)}")
            raise HTTPException(status_code=400, detail="На удалось извлечь сохраненные учетные данные из СУБД панели.")

    # Собираем конфигурационный словарь для прямого коннекта
    target_config = {
        "host": req.host,
        "port": req.port,
        "user": req.db_user,
        "password": target_password,
        "dbname": req.dbname,
        "connect_timeout": 2  # ИБ-ФИКС: Передаем строго INTEGER, гарантируя жесткий сброс сессии через 5 секунд!
    }

    # Локализуем сетевую разведку глубоко внутри блока try-except
    try:
        # Пытаемся установить соединение с удаленным узлом СУБД
        with connect(**target_config) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # Выполняем легковесный strict-запрос для проверки реального отклика ядра PostgreSQL
                cur.execute("SELECT 1;")
                cur.fetchone()

                # Логируем УСПЕШНУЮ ИБ-разведку во внутреннюю таблицу СУБД панели
                utils.log_operation(
                    "PANEL_MANAGER",
                    str(current_user),
                    f"server.{req.server_id or req.host}",
                    "TEST_CONNECTION",
                    "INFRASTRUCTURE",
                    "success",
                    f"Успешная проверка связи с узлом СУБД: {req.host}"
                )

                # # ИБ-ЛОГ: Дублируем успех в системный лог операционной системы
                logger.info(f"[ИБ-АУДИТ] <<< Связь с узлом СУБД {req.host}:{req.port} УСПЕШНО установлена. Администратор: '{current_user}'")
                return {"status": "success", "message": "Подключение успешно установлено!"}

    except Exception as e:
        err_msg = str(e)
        
        # Логируем НЕУСПЕШНЫЙ тест подключения во внутреннюю таблицу для фиксации аномалий
        try:
            utils.log_operation(
                "PANEL_MANAGER",
                str(current_user),
                f"server.{req.server_id or req.host}",
                "TEST_CONNECTION",
                "INFRASTRUCTURE",
                "error",
                f"Сбой теста связи с узлом СУБД {req.host}. Ошибка: {err_msg}"
            )
        except Exception:
            pass # Локальная страховка на случай, если упала сама база панели

        # КРИТИЧНО ДЛЯ ИБ: Записываем сетевой сбой в логгер ОС с подробным описанием (БЕЗ ПАРОЛЯ!)
        logger.error(f"[ИБ-АУДИТ] !!! СБОЙ ПОДКЛЮЧЕНИЯ | Не удалось связаться с СУБД {req.host}:{req.port}. Запрос от '{current_user}'. Причина: {err_msg}")
        
        # Возвращаем аккуратный 400 вместо падения рантайма в deadlock [INDEX_0.1.12]
        raise HTTPException(
            status_code=400, 
            detail=f"Сбой подключения: Не удалось установить связь с удаленным сервером PostgreSQL. Проверьте настройки сети и Firewall. ({err_msg})"
        )


# =========================================================================
# # 5. СПИСКИ ДЛЯ ДИНАМИЧЕСКИХ СЕЛЕКТОРОВ
# =========================================================================

# --- 1. СЕЛЕКТОР БАЗ ДАННЫХ ---
@app.get("/api/get-target-databases/{server_id}")
@app.get("/api/get-target-databases/{server_id}/")
def get_target_databases(server_id: str, current_user: str = Depends(utils.get_current_user)):
    logger.info(f"[ИБ-АУДИТ] >>> Запрос списка БД. Пользователь: '{current_user}', Сервер: '{server_id}'")
    server_config = utils.get_server_from_db(server_id)
    server_config["connect_timeout"] = 5  # Защита от бесконечного зависания сети

    try:
        with connect(**server_config) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                try:
                    cur.execute("SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname;")
                    dbs = [row[0] for row in cur.fetchall() if row]
                except Exception as sql_err:
                    logger.error(f"[ИБ-ОТКАЗ] Ошибка СУБД при выкачивании баз данных: {str(sql_err)}")
                    raise HTTPException(status_code=422, detail="Удаленный сервер отклонил запрос списка баз данных.")

                logger.info(f"[ИБ-АУДИТ] <<< Список БД успешно отдан пользователю '{current_user}'. Найдено баз: {len(dbs)}")
                return {"databases": dbs}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[ИБ-КРАХ] Сетевой сбой получения БД на сервере '{server_id}' пользователем '{current_user}': {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Ошибка подключения к удаленному серверу СУБД (Таймаут).")


# --- 2. СЕЛЕКТОР СХЕМ ---
@app.get("/api/get-target-schemas/{server_id}")
@app.get("/api/get-target-schemas/{server_id}/")
def get_target_schemas(server_id: str, db: str, current_user: str = Depends(utils.get_current_user)):
    logger.info(f"[ИБ-АУДИТ] >>> Запрос списка схем. Пользователь: '{current_user}', Сервер: '{server_id}', База: '{db}'")
    
    # ИБ-СТРАХОВКА: Если фронтенд выбрал веер ALL, отдаем статичный маркер без мучений удаленной СУБД
    if db.upper() == "ALL":
        return {"schemas": ["ALL"]}

    server_config = utils.get_server_from_db(server_id)
    server_config["dbname"] = db
    server_config["connect_timeout"] = 5

    try:
        with connect(**server_config) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                try:
                    cur.execute("""
                        SELECT schema_name FROM information_schema.schemata 
                        WHERE schema_name NOT LIKE 'pg_%' AND schema_name != 'information_schema' 
                        ORDER BY schema_name;
                    """)
                    schemas = [row[0] for row in cur.fetchall() if row]
                except Exception as sql_err:
                    logger.error(f"[ИБ-ОТКАЗ] Ошибка СУБД при выкачивании схем: {str(sql_err)}")
                    raise HTTPException(status_code=422, detail="Удаленный сервер отклонил запрос списка схем.")

                logger.info(f"[ИБ-АУДИТ] <<< Список схем успешно отдан пользователю '{current_user}'. Найдено схем: {len(schemas)}")
                return {"schemas": schemas}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[ИБ-КРАХ] Сетевой сбой получения схем в БД '{db}' на сервере '{server_id}': {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Ошибка извлечения схем данных (Таймаут).")


# --- 3. СЕЛЕКТОР ТАБЛИЦ ---
@app.get("/api/get-target-tables/{server_id}")
@app.get("/api/get-target-tables/{server_id}/")
def get_target_tables(server_id: str, db: str, schema: str, current_user: str = Depends(utils.get_current_user)):
    logger.info(f"[ИБ-АУДИТ] >>> Запрос списка таблиц. Пользователь: '{current_user}', Сервер: '{server_id}', База: '{db}', Схема: '{schema}'")
    
    if db.upper() == "ALL" or schema.upper() == "ALL":
        return {"tables": ["ALL"]}

    server_config = utils.get_server_from_db(server_id)
    server_config["dbname"] = db
    server_config["connect_timeout"] = 5

    try:
        with connect(**server_config) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                try:
                    cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = %s ORDER BY table_name;", (schema,))
                    tables = [row[0] for row in cur.fetchall() if row]
                except Exception as sql_err:
                    logger.error(f"[ИБ-ОТКАЗ] Ошибка СУБД при выкачивании таблиц: {str(sql_err)}")
                    raise HTTPException(status_code=422, detail="Удаленный сервер отклонил запрос списка таблиц.")

                logger.info(f"[ИБ-АУДИТ] <<< Список таблиц успешно отдан пользователю '{current_user}'. Найдено таблиц: {len(tables)}")
                return {"tables": tables}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[ИБ-КРАХ] Сетевой сбой получения таблиц в '{db}.{schema}' на сервере '{server_id}': {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Ошибка перечисления таблиц.")


# --- 4. СЕЛЕКТОР РОЛЕЙ/ПОЛЬЗОВАТЕЛЕЙ ---
@app.get("/api/get-target-roles/{server_id}")
@app.get("/api/get-target-roles/{server_id}/")
def get_target_roles(server_id: str, show_system: bool = Query(False), current_user: str = Depends(utils.get_current_user)):
    logger.info(f"[ИБ-АУДИТ] >>> Запрос списка ролей. Пользователь: '{current_user}', Сервер: '{server_id}', Системные: {show_system}")
    server_config = utils.get_server_from_db(server_id)
    server_config["connect_timeout"] = 5

    condition = "LIKE" if show_system else "NOT LIKE"
    query = f"SELECT rolname FROM pg_roles WHERE rolname {condition} 'pg_%' OR rolname NOT LIKE 'pg_%' ORDER BY rolname;"
    
    # Если show_system=False, строго отсекаем системные роли
    if not show_system:
        query = "SELECT rolname FROM pg_roles WHERE rolname NOT LIKE 'pg_%' ORDER BY rolname;"

    try:
        with connect(**server_config) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                try:
                    cur.execute(query)
                    roles = [row[0] for row in cur.fetchall() if row]
                except Exception as sql_err:
                    logger.error(f"[ИБ-ОТКАЗ] Ошибка СУБД при выкачивании ролей: {str(sql_err)}")
                    raise HTTPException(status_code=422, detail="Удаленный сервер отклонил запрос ролей безопасности.")

                logger.info(f"[ИБ-АУДИТ] <<< Список ролей успешно отдан пользователю '{current_user}'. Найдено ролей: {len(roles)}")
                return {"roles": roles}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[ИБ-КРАХ] Сетевой сбой получения ролей на сервере '{server_id}': {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Ошибка чтения ролей безопасности СУБД.")



# =========================================================================
# # 6. УПРАВЛЕНИЕ ПРАВАМИ
# =========================================================================
@app.post("/api/manage-privileges")
@app.post("/api/manage-privileges/")
def manage_db_privileges(
    req: dict, 
    current_user: str = Depends(RoleChecker(["admin"]))
):
    target_server = req.get("target_server", "").strip()
    target_db_param = req.get("target_db", "").strip()
    username = req.get("username", "").strip()
    scope = req.get("scope", "").strip().upper()
    schema_param = req.get("schema_name", "public").strip()
    table_name = req.get("table_name", "ALL").strip()
    action = req.get("action", "GRANT").strip().upper()
    privilege_raw = req.get("privilege", "").strip()

    if not target_server or not target_db_param or not username or not privilege_raw:
        raise HTTPException(status_code=400, detail="Отсутствуют обязательные параметры конфигурации доступов.")

    if action not in ["GRANT", "REVOKE"]:
        raise HTTPException(status_code=400, detail=f"Недопустимое действие СУБД: {action}")

    server_config = utils.get_server_from_db(target_server)
    action_keyword = "GRANT" if action == "GRANT" else "REVOKE"
    user_ident = sql.Identifier(username)
    
    privileges_list = [p.strip().upper() for p in privilege_raw.split(",") if p.strip()]
    priv_sql = sql.SQL("ALL") if "ALL" in privileges_list else sql.SQL(", ").join(sql.SQL(p) for p in privileges_list)

    logger.info(f"[ИБ-АУДИТ] >>> СТАРТ ВЕЕРНОЙ ТРАНЗАКЦИИ | Оператор: '{current_user}' | Кластер: '{target_server}'")

    # ШАГ А: Динамическое определение целевых баз данных на кластере
    resolved_databases = []
    try:
        base_config = server_config.copy()
        base_config["dbname"] = "postgres"
        
        with connect(**base_config) as init_conn:
            with init_conn.cursor() as init_cur:
                if target_db_param.upper() == "ALL":
                    init_cur.execute("""
                        SELECT datname FROM pg_database 
                        WHERE datistemplate = false 
                        AND datname NOT IN ('postgres', 'information_schema')
                        AND datallowconn = true;
                    """)
                    resolved_databases = [row for row in init_cur.fetchall() if row and row]
                else:
                    resolved_databases = [target_db_param]
    except Exception as env_err:
        logger.error(f"[ИБ-КРАХ] Не удалось собрать карту баз данных кластера: {str(env_err)}")
        raise HTTPException(status_code=500, detail="Ошибка карты баз данных кластера.")
    # ШАГ Б: Запуск сквозного итератора сессий по массиву resolved_databases
    executed_queries_count = 0
    errors_list = []

    for current_db in resolved_databases:
        db_config = server_config.copy()
        db_config["dbname"] = current_db
        
        try:
            with connect(**db_config) as conn:
                conn.autocommit = True
                with conn.cursor() as cur:
                    # Извлекаем схемы внутри ТЕКУЩЕЙ базы данных
                    target_schemas = []
                    if schema_param.upper() == "ALL":
                        cur.execute("""
                            SELECT schema_name FROM information_schema.schemata
                            WHERE schema_name NOT IN ('information_schema', 'pg_catalog')
                            AND schema_name NOT LIKE 'pg_toast%' AND schema_name NOT LIKE 'pg_temp%';
                        """)
                        target_schemas = [row[0] for row in cur.fetchall() if row and row[0]]
                    else:
                        target_schemas = [s.strip() for s in schema_param.split(",") if s.strip()]

                    if not target_schemas:
                        target_schemas = ["public"]

                    queries_to_execute = []
                    obj_name = ""

                    # --- УРОВЕНЬ БАЗЫ ДАННЫХ
                    if scope == "DATABASE":
                        if action_keyword == "GRANT":
                            queries_to_execute.append(sql.SQL("GRANT {privs} ON DATABASE {db} TO {user};").format(privs=priv_sql, db=sql.Identifier(current_db), user=user_ident))
                        else:
                            queries_to_execute.append(sql.SQL("REVOKE {privs} ON DATABASE {db} FROM {user};").format(privs=priv_sql, db=sql.Identifier(current_db), user=user_ident))
                        obj_name = current_db

                    # --- УРОВЕНЬ СХЕМЫ
                    elif scope == "SCHEMA":
                        for sch in target_schemas:
                            if not sch: continue
                            if action_keyword == "GRANT":
                                queries_to_execute.append(sql.SQL("GRANT {privs} ON SCHEMA {sch} TO {user};").format(privs=priv_sql, sch=sql.Identifier(sch), user=user_ident))
                            else:
                                queries_to_execute.append(sql.SQL("REVOKE {privs} ON SCHEMA {sch} FROM {user};").format(privs=priv_sql, sch=sql.Identifier(sch), user=user_ident))
                        obj_name = schema_param

                    # --- УРОВЕНЬ ТАБЛИЦЫ
                    elif scope in ["TABLE", "DEFAULT_TABLE"]:
                        for sch in target_schemas:
                            if not sch: continue
                            sch_ident = sql.Identifier(sch)
                            
                            if table_name.upper() == "ALL" or table_name.strip() == "" or scope == "DEFAULT_TABLE":
                                if action_keyword == "GRANT":
                                    queries_to_execute.append(sql.SQL("GRANT {privs} ON ALL TABLES IN SCHEMA {sch} TO {user};").format(privs=priv_sql, sch=sch_ident, user=user_ident))
                                else:
                                    queries_to_execute.append(sql.SQL("REVOKE {privs} ON ALL TABLES IN SCHEMA {sch} FROM {user};").format(privs=priv_sql, sch=sch_ident, user=user_ident))
                            else:
                                obj_name = table_name
                                tables = [t.strip() for t in table_name.split(",") if t.strip()]
                                for t in tables:
                                    if action_keyword == "GRANT":
                                        queries_to_execute.append(sql.SQL("GRANT {privs} ON TABLE {tbl} TO {user};").format(privs=priv_sql, tbl=sql.Identifier(sch, t), user=user_ident))
                                    else:
                                        queries_to_execute.append(sql.SQL("REVOKE {privs} ON TABLE {tbl} FROM {user};").format(privs=priv_sql, tbl=sql.Identifier(sch, t), user=user_ident))

                            if table_name.upper() == "ALL" or table_name.strip() == "" or scope == "DEFAULT_TABLE":
                                # Извлекаем текстовое имя овнера схемы через pg_roles
                                cur.execute("""
                                    SELECT r.rolname FROM pg_namespace n
                                    JOIN pg_roles r ON n.nspowner = r.oid
                                    WHERE n.nspname = %s;
                                """, (sch,))
                                schema_owner_row = cur.fetchone()
                                schema_owner = schema_owner_row[0] if schema_owner_row else ""
                                
                                # ПРАВИЛО 1: Накат дефолтов от имени реального создателя (овнера) схемы
                                if schema_owner:
                                    for_role_clause = sql.SQL("FOR ROLE {creator}").format(creator=sql.Identifier(schema_owner))
                                    if action_keyword == "GRANT":
                                        queries_to_execute.append(sql.SQL("ALTER DEFAULT PRIVILEGES {for_role} IN SCHEMA {sch} GRANT {privs} ON TABLES TO {user};").format(for_role=for_role_clause, sch=sch_ident, privs=priv_sql, user=user_ident))
                                    else:
                                        queries_to_execute.append(sql.SQL("ALTER DEFAULT PRIVILEGES {for_role} IN SCHEMA {sch} REVOKE {privs} ON TABLES FROM {user};").format(for_role=for_role_clause, sch=sch_ident, privs=priv_sql, user=user_ident))

                                # ПРАВИЛО 2: Накат дефолтов для суперадминистратора postgres
                                if schema_owner != "postgres":
                                    for_postgres_clause = sql.SQL("FOR ROLE postgres")
                                    if action_keyword == "GRANT":
                                        queries_to_execute.append(sql.SQL("ALTER DEFAULT PRIVILEGES {for_role} IN SCHEMA {sch} GRANT {privs} ON TABLES TO {user};").format(for_role=for_postgres_clause, sch=sch_ident, privs=priv_sql, user=user_ident))
                                    else:
                                        queries_to_execute.append(sql.SQL("ALTER DEFAULT PRIVILEGES {for_role} IN SCHEMA {sch} REVOKE {privs} ON TABLES FROM {user};").format(for_role=for_postgres_clause, sch=sch_ident, privs=priv_sql, user=user_ident))
                                
                                obj_name = f"TABLES_AND_DEFAULTS_IN_{schema_param}"
                    # --- УРОВЕНЬ ПОСЛЕДОВАТЕЛЬНОСТЕЙ
                    elif scope in ["SEQUENCE", "DEFAULT_SEQUENCE"]:
                        for sch in target_schemas:
                            if not sch: continue
                            sch_ident = sql.Identifier(sch)
                            
                            if table_name.upper() == "ALL" or table_name.strip() == "" or scope == "DEFAULT_SEQUENCE":
                                if action_keyword == "GRANT":
                                    queries_to_execute.append(sql.SQL("GRANT {privs} ON ALL SEQUENCES IN SCHEMA {sch} TO {user};").format(privs=priv_sql, sch=sch_ident, user=user_ident))
                                else:
                                    queries_to_execute.append(sql.SQL("REVOKE {privs} ON ALL SEQUENCES IN SCHEMA {sch} FROM {user};").format(privs=priv_sql, sch=sch_ident, user=user_ident))
                            else:
                                obj_name = table_name
                                sequences = [seq.strip() for seq in table_name.split(",") if seq.strip()]
                                for seq in sequences:
                                    if action_keyword == "GRANT":
                                        queries_to_execute.append(sql.SQL("GRANT {privs} ON SEQUENCE {seq} TO {user};").format(privs=priv_sql, seq=sql.Identifier(sch, seq), user=user_ident))
                                    else:
                                        queries_to_execute.append(sql.SQL("REVOKE {privs} ON SEQUENCE {seq} FROM {user};").format(privs=priv_sql, seq=sql.Identifier(sch, seq), user=user_ident))

                            if table_name.upper() == "ALL" or table_name.strip() == "" or scope == "DEFAULT_SEQUENCE":
                                # Извлекаем текстовое имя овнера схемы через pg_roles для сиквенсов
                                cur.execute("""
                                    SELECT r.rolname FROM pg_namespace n
                                    JOIN pg_roles r ON n.nspowner = r.oid
                                    WHERE n.nspname = %s;
                                """, (sch,))
                                schema_owner_row = cur.fetchone()
                                schema_owner = schema_owner_row[0] if schema_owner_row else ""
                                
                                # ПРАВИЛО 1: Накат дефолтов от имени создателя (овнера) схемы
                                if schema_owner:
                                    for_role_clause = sql.SQL("FOR ROLE {creator}").format(creator=sql.Identifier(schema_owner))
                                    if action_keyword == "GRANT":
                                        queries_to_execute.append(sql.SQL("ALTER DEFAULT PRIVILEGES {for_role} IN SCHEMA {sch} GRANT {privs} ON SEQUENCES TO {user};").format(for_role=for_role_clause, sch=sch_ident, privs=priv_sql, user=user_ident))
                                    else:
                                        queries_to_execute.append(sql.SQL("ALTER DEFAULT PRIVILEGES {for_role} IN SCHEMA {sch} REVOKE {privs} ON SEQUENCES FROM {user};").format(for_role=for_role_clause, sch=sch_ident, privs=priv_sql, user=user_ident))

                                # ПРАВИЛО 2: Накат дефолтов сиквенсов для суперадминистратора postgres
                                if schema_owner != "postgres":
                                    for_postgres_clause = sql.SQL("FOR ROLE postgres")
                                    if action_keyword == "GRANT":
                                        queries_to_execute.append(sql.SQL("ALTER DEFAULT PRIVILEGES {for_role} IN SCHEMA {sch} GRANT {privs} ON SEQUENCES TO {user};").format(for_role=for_postgres_clause, sch=sch_ident, privs=priv_sql, user=user_ident))
                                    else:
                                        queries_to_execute.append(sql.SQL("ALTER DEFAULT PRIVILEGES {for_role} IN SCHEMA {sch} REVOKE {privs} ON SEQUENCES FROM {user};").format(for_role=for_postgres_clause, sch=sch_ident, privs=priv_sql, user=user_ident))
                                
                                obj_name = f"SEQUENCES_AND_DEFAULTS_IN_{schema_param}"

                    if not queries_to_execute:
                        continue

                    # Поэтапное атомарное выполнение DDL/DCL пакета внутри текущей СУБД
                    import time
                    for query_data in queries_to_execute:
                        try:
                            cur.execute(query_data)
                        except Exception as sql_exec_err:
                            err_msg = str(sql_exec_err).lower()
                            if "lock" in err_msg or "deadlock" in err_msg or "tuple" in err_msg or "concurrent" in err_msg:
                                try:
                                    time.sleep(0.1)
                                    cur.execute(query_data)
                                    continue
                                except Exception:
                                    pass
                            if "не существует" in err_msg or "does not exist" in err_msg or "undefined" in err_msg:
                                raise sql_exec_err
                            continue

                    executed_queries_count += 1
                    current_log_obj = f"{current_db}.{obj_name}"
                    
                    # Логируем успешное выполнение для каждой базы
                    utils.log_operation(target_server, username, current_log_obj, f"{action_keyword}_{scope}", privilege_raw, "success", admin_username=current_user)
                    logger.info(f"[ИБ-АУДИТ] <<< УСПЕХ ИЗМЕНЕНИЯ ПРАВ | База '{current_db}' | Объекты: {current_log_obj}")

        except Exception as db_loop_err:
            err_str = str(db_loop_err)
            errors_list.append(f"Ошибка в базе {current_db}: {err_str}")
            utils.log_operation(target_server, username, f"{current_db}.ERROR", f"{action_keyword}_{scope}", privilege_raw, "error", err_str, admin_username=current_user)
            logger.error(f"[ИБ-КРАХ] Не удалось применить права в базе '{current_db}': {err_str}")
            continue

    # Финальный анализ результатов веерного прохода по кластеру
    if executed_queries_count == 0 and errors_list:
        raise HTTPException(status_code=500, detail=f"Фатальный сбой наката на все базы данных: {'; '.join(errors_list[:2])}")

    return {
        "status": "success", 
        "message": f"Права успешно применены! Обработано баз данных: {executed_queries_count}. Ошибок: {len(errors_list)}."
    }


# =========================================================================
# # 7. УПРАВЛЕНИЕ СИСТЕМНЫМИ РОЛЯМИ (СТРОГО ДЛЯ ADMIN И SECURITY_MANAGER)
# =========================================================================
@app.post("/api/manage-system-roles")
@app.post("/api/manage-system-roles/")
def manage_system_roles(
    req: SystemRoleManagerRequest,
    current_user: str = Depends(RoleChecker(["admin", "Security_Manager"]))
):
    # ИБ-ЛОГ: Фиксируем старт критической операции назначения/отзыва глобальных ролей СУБД
    logger.info(f"[ИБ-АУДИТ] >>> ЗАПРОС СИСТЕМНОЙ РОЛИ | Администратор: '{current_user}' | Целевой сервер: '{req.target_server}' | Действие: {req.action.upper()} | Роль: '{req.system_role}' -> Пользователь: '{req.username}'")

    server_config = utils.get_server_from_db(req.target_server)
    action_keyword = "GRANT" if req.action.upper() == "GRANT" else "REVOKE"

    # Безопасное формирование SQL через Identifier для защиты от SQL-инъекций
    if action_keyword == "GRANT":
        query = sql.SQL("GRANT {} TO {};").format(sql.Identifier(req.system_role), sql.Identifier(req.username))
    else:
        query = sql.SQL("REVOKE {} FROM {};").format(sql.Identifier(req.system_role), sql.Identifier(req.username))

    try:
        with connect(**server_config) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                
                # -------------------------------------------------------------------------
                # ИБ-ЗАЩИТА: Локальный перехват ошибок синтаксиса и отсутствующих объектов
                # -------------------------------------------------------------------------
                try:
                    cur.execute(query)
                except Exception as sql_exec_err:
                    err_msg = str(sql_exec_err)
                    logger.warning(f"[ИБ-ОТКАЗ] СУБД отклонила команду назначения системной роли: {err_msg}")
                    
                    # Фиксируем сбой операции во внутренней таблице аудита панели
                    utils.log_operation(
                        target_server=req.target_server,
                        username=req.username,
                        table_name=req.system_role,
                        action=f"{action_keyword}_SYSTEM_ROLE",
                        privilege="MEMBERSHIP",
                        status="error",
                        error_message=err_msg,
                        admin_username=current_user
                    )
                    
                    # Выбрасываем корректный 422 вместо падения всего uvicorn в deadlock
                    raise HTTPException(
                        status_code=422, 
                        detail=f"Ошибка PostgreSQL: Целевой объект или роль не найдены. Подробно: {err_msg}"
                    )

                # --- ШТАТНЫЙ КОД ПРИ УСПЕШНОМ ВЫПОЛНЕНИИ ---
                # Senior ИБ-Фикс: Запись во внутреннюю таблицу аудита панели
                utils.log_operation(
                    target_server=req.target_server,
                    username=req.username,
                    table_name=req.system_role,
                    action=f"{action_keyword}_SYSTEM_ROLE",
                    privilege="MEMBERSHIP",
                    status="success",
                    admin_username=current_user
                )

                logger.info(f"[ИБ-АУДИТ] <<< УСПЕХ СИСТЕМНОЙ РОЛИ | Глобальный статус пользователя '{req.username}' успешно изменен администратором '{current_user}' ({action_keyword} {req.system_role}).")
                return {"status": "success", "message": f"Роль {req.system_role} успешно изменена"}

    except HTTPException:
        # Пробрасываем наш HTTPException (422) дальше на фронтенд без изменений
        raise
    except Exception as general_err:
        # Резервный верхнеуровневый перехват для сетевых крахов (например, если упал сам хост СУБД)
        err_msg = str(general_err)
        logger.error(f"[ИБ-КРАХ] Фатальная ошибка связи с сервером для '{req.username}' администратором '{current_user}': {err_msg}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Ошибка изменения системной роли на удаленном сервере СУБД. Проверьте сеть: {err_msg}")


# =========================================================================
# # 8. АУДИТ
# =========================================================================
@app.get("/api/audit/")
@app.get("/api/audit")
def get_audit_logs(
    page: int = 1,
    size: int = 20,
    username: Optional[str] = None,
    target_server: Optional[str] = None,
    action: Optional[str] = None,
    timestamp: Optional[str] = None,
    admin_username: Optional[str] = None,
    current_user: str = Depends(RoleChecker(["admin", "auditor"]))
):
    # ИБ-ЛОГ: Фиксируем, КТО именно просматривает системный журнал аудита и с какими фильтрами
    logger.info(
        f"[ИБ-АУДИТ] >>> Чтение журнала логов. Пользователь: '{current_user}' | "
        f"Фильтры -> username: {username}, server: {target_server}, action: {action}, "
        f"admin: {admin_username}, page: {page}"
    )

    offset = (page - 1) * size

    if utils.db_pool is None:
        utils.init_pool()

    count_query = "SELECT COUNT(*) FROM audit_logs"
    data_query = "SELECT log_id, timestamp, target_server, username, table_name, action, privilege, status, error_message, admin_username FROM audit_logs"

    conditions = []
    params = []

    # ИБ-ФИКС: Оптимизированный сбор динамических условий совместного поиска
    if username:
        conditions.append("username ILIKE %s")
        params.append(f"%{username}%")

    if target_server:
        conditions.append("target_server = %s")
        params.append(target_server)

    if action:
        conditions.append("action ILIKE %s")
        params.append(f"%{action}%")

    if timestamp:
        if "." in timestamp:
            conditions.append("timestamp::date = to_date(%s, 'DD.MM.YYYY')")
        else:
            conditions.append("timestamp::date = to_date(%s, 'YYYY-MM-DD')")
        params.append(timestamp)

    if admin_username:
        conditions.append("admin_username ILIKE %s")
        params.append(f"%{admin_username}%")

    if conditions:
        where_clause = " WHERE " + " AND ".join(conditions)
        count_query += where_clause
        data_query += where_clause

    data_query += " ORDER BY log_id DESC LIMIT %s OFFSET %s"

    try:
        with utils.db_pool.connection() as conn:
            with conn.cursor() as cursor:
                
                # Локальный перехват ошибок СУБД для предотвращения зависания потоков
                try:
                    # Считаем общее количество записей для пагинации фронтенда
                    cursor.execute(count_query, tuple(params))
                    total = cursor.fetchone()[0]

                    # Выбираем пагинированную порцию логов
                    data_params = params + [size, offset]
                    cursor.execute(data_query, tuple(data_params))
                    
                    columns = [desc[0] for desc in cursor.description]
                    raw_rows = cursor.fetchall()
                except Exception as sql_err:
                    logger.error(f"[ИБ-ОТКАЗ] База данных отклонила чтение журнала логов: {str(sql_err)}")
                    raise HTTPException(status_code=422, detail="СУБД отклонила поисковый запрос журнала аудита.")

                logs = []
                for row in raw_rows:
                    log_entry = dict(zip(columns, row))
                    ts_val = log_entry.get('timestamp')
                    
                    # ИБ-ФИКС: Пуленепробиваемая конвертация даты (страховка от AttributeError)
                    if ts_val:
                        if hasattr(ts_val, 'strftime'):
                            log_entry['timestamp'] = ts_val.strftime("%Y-%m-%d %H:%M:%S")
                        else:
                            # Если дата прилетела строкой из СУБД, отдаем как есть, не ломая рантайм
                            log_entry['timestamp'] = str(ts_val)
                    else:
                        log_entry['timestamp'] = "Не указано"

                    logs.append(log_entry)

                # ИБ-ЛОГ: УСПЕШНОЕ ЗАВЕРШЕНИЕ ВЫГРУЗКИ ЖУРНАЛА СУБД
                logger.info(f"[ИБ-АУДИТ] <<< Журнал успешно отдан пользователю '{current_user}'. Передано строк: {len(logs)} из {total}")
                return {"total": total, "page": page, "size": size, "logs": logs}

    except HTTPException:
        raise
    except Exception as e:
        # КРИТИЧНО ДЛЯ ИБ: Записываем сбой парсинга SQL или падение пула в логи ОС с трассировкой
        logger.error(f"[ИБ-КРАХ] Ошибка чтения журнала аудита для пользователя '{current_user}': {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Ошибка извлечения данных из системного журнала аудита.")


# =========================================================================
# # ИБ-ЭНДПОИНТ: СЛУЖИТ ДЛЯ ВЕРИФИКАЦИИ РОЛИ ТЕКУЩЕЙ СЕССИИ НА ФРОНТЕНДЕ
# =========================================================================
@app.get("/api/auth/verify-role")
@app.get("/api/auth/verify-role/")
def verify_current_session_role(
    request: Request,
    token: str = Depends(utils.oauth2_scheme)
):
    try:
        # Декодируем и проверяем криптографическую подпись токена
        payload = jwt.decode(token, utils.JWT_SECRET, algorithms=[utils.JWT_ALGORITHM])
        
        # Успешный проход оставляем "тихим", чтобы не спамить в диск
        return {
            "status": "success",
            "username": payload.get("sub"),
            "role": payload.get("role")
        }

    # ИБ-ФИКС: Разделяем штатное протухание сессии и целенаправленную атаку
    except jwt.ExpiredSignatureError as exp_err:
        client_ip = request.headers.get("x-real-ip") or request.client.host
        # Протухший токен — это штатное поведение интерфейса, пишем в INFO
        logger.info(f"[ИБ-СЕССИЯ] Истек срок действия токена. IP пользователя: {client_ip}")
        raise HTTPException(status_code=401, detail="Сессия невалидна (Истекла)")

    except jwt.PyJWTError as e:
        # Извлекаем реальный IP-адрес через наш прокси-контур Nginx
        client_ip = request.headers.get("x-real-ip") or request.client.host
        
        # КРИТИЧНО ДЛЯ ИБ: Сюда попадают только битые или поддельные токены. Это АТАКА!
        logger.critical(
            f"[ИБ-АУДИТ] !!! КРИТИЧЕСКАЯ КОМПРОМЕТАЦИЯ СЕССИИ | Обнаружен поддельный JWT-токен! "
            f"IP атакующего: {client_ip} | Причина сбоя: {str(e)}"
        )
        raise HTTPException(status_code=401, detail="Сессия невалидна")
