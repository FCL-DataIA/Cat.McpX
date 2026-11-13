import os
import re
import json
import time
import uuid
import asyncio
import inspect
import logging
import functools
from html.parser import HTMLParser
from urllib.parse import quote_plus, urlsplit
from typing import Optional, Dict, Any, Tuple

import httpx
import psycopg
from psycopg_pool import AsyncConnectionPool
import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

# --- CONFIGURATION DU LOGGING ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-pndb-v2.1")

audit_handler = logging.StreamHandler()
audit_handler.setFormatter(logging.Formatter("%(message)s"))
audit_logger = logging.getLogger("mcp-pndb.audit")
audit_logger.propagate = False
audit_logger.addHandler(audit_handler)


# --- BASE DE DONNÉES POSTGRESQL (HYPERFLUID) ---
def _clean_env_val(val: Optional[str]) -> Optional[str]:
    if not val:
        return None
    cleaned = val.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {'"', "'"}:
        cleaned = cleaned[1:-1].strip()
    return cleaned or None


def _normalize_pg_url(url: str) -> str:
    url = url.strip()
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    sslmode = _clean_env_val(os.getenv("DB_SSLMODE")) or _clean_env_val(os.getenv("PGSSLMODE"))
    if sslmode and "sslmode=" not in url:
        sep = "&" if "?" in url else "?"
        url += f"{sep}sslmode={sslmode}"
    return url


def _extract_pg_url_from_json(raw: Optional[str]) -> Optional[str]:
    """Extrait l'URL PostgreSQL si Hyperfluid a injecté un bloc JSON d'identifiants."""
    cleaned = _clean_env_val(raw)
    if not cleaned:
        return None

    # Gère les guillemets échappés (ex: {\"database\":...})
    unescaped = cleaned.replace('\\"', '"') if '\\"' in cleaned else cleaned

    # 1. Parsing JSON standard si la chaîne contient un objet {...}
    start_idx = unescaped.find("{")
    end_idx = unescaped.rfind("}")
    if start_idx != -1 and end_idx > start_idx:
        json_candidate = unescaped[start_idx:end_idx + 1]
        try:
            data = json.loads(json_candidate)
            if isinstance(data, dict):
                for key in ("internal_database_url", "database_url", "url", "uri", "external_database_url"):
                    candidate = data.get(key)
                    if isinstance(candidate, str) and candidate.strip():
                        return _normalize_pg_url(candidate)

                user = data.get("username") or data.get("user") or data.get("db_user")
                password = data.get("password") or data.get("db_password") or ""
                host = data.get("internal_host") or data.get("internal-host") or data.get("host") or data.get("db_host")
                port = data.get("internal_port") or data.get("internal-port") or data.get("port") or data.get("db_port") or "5432"
                name = data.get("database") or data.get("database_name") or data.get("dbname") or data.get("name")

                if user and host and name:
                    auth = quote_plus(str(user)) + (f":{quote_plus(str(password))}" if password else "")
                    return _normalize_pg_url(f"postgresql://{auth}@{host}:{port}/{name}")
        except Exception:
            pass

    # 2. Repli par expression régulière si le JSON est tronqué ou contient des caractères non échappés
    match = re.search(r'"internal_database_url"\s*:\s*"(postgres(?:ql)?://[^"]+)"', unescaped)
    if match:
        return _normalize_pg_url(match.group(1))

    return None


def _first_env(*names: str) -> Optional[str]:
    for name in names:
        val = _clean_env_val(os.getenv(name))
        if val:
            return val
    return None


def _build_database_url() -> Optional[str]:
    # 1. Priorité absolue : extraire l'URL propre si un bloc JSON Hyperfluid existe dans l'environnement
    # (y compris s'il a été interpolé dans DATABASE_URL)
    for env_val in os.environ.values():
        if env_val and ("internal_database_url" in env_val or "internal_host" in env_val):
            from_json = _extract_pg_url_from_json(env_val)
            if from_json:
                return from_json

    # 2. Vérifie DATABASE_URL s'il s'agit d'une URL directe valide
    cleaned_db_url = _clean_env_val(os.getenv("DATABASE_URL"))
    if cleaned_db_url and "{" not in cleaned_db_url:
        return _normalize_pg_url(cleaned_db_url)

    # 3. Assemblage à partir des variables unitaires
    user = _first_env("DB_USER", "username", "POSTGRES_USER", "PGUSER")
    password = _first_env("DB_PASSWORD", "password", "POSTGRES_PASSWORD", "PGPASSWORD") or ""
    host = _first_env("DB_HOST", "internal_host", "internal-host", "POSTGRES_HOST", "PGHOST")
    port = _first_env("DB_PORT", "internal_port", "internal-port", "POSTGRES_PORT", "PGPORT") or "5432"
    name = _first_env("DB_NAME", "database", "database_name", "POSTGRES_DB", "PGDATABASE")

    if not (user and host and name) or user.startswith("{"):
        return None

    auth = quote_plus(user) + (f":{quote_plus(password)}" if password else "")
    return _normalize_pg_url(f"postgresql://{auth}@{host}:{port}/{name}")


DATABASE_URL = _build_database_url()

_db_pool: Optional[AsyncConnectionPool] = None
_db_lock = asyncio.Lock()
_db_next_retry_at: float = 0.0
_background_tasks: set[asyncio.Task] = set()

DB_SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS mcp_tool_logs (
        id BIGSERIAL PRIMARY KEY,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        tool_name TEXT NOT NULL,
        args JSONB NOT NULL DEFAULT '{}'::jsonb,
        dataset_id TEXT,
        status TEXT NOT NULL,
        duration_ms DOUBLE PRECISION NOT NULL,
        response_chars INTEGER NOT NULL DEFAULT 0,
        est_tokens INTEGER NOT NULL DEFAULT 0,
        error_message TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_mcp_tool_logs_created_at ON mcp_tool_logs (created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_mcp_tool_logs_tool_name ON mcp_tool_logs (tool_name)",
    "CREATE INDEX IF NOT EXISTS idx_mcp_tool_logs_dataset_id ON mcp_tool_logs (dataset_id) WHERE dataset_id IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS idx_mcp_tool_logs_status ON mcp_tool_logs (status)",
    """
    CREATE TABLE IF NOT EXISTS mcp_http_logs (
        id BIGSERIAL PRIMARY KEY,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        req_id TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        duration_ms DOUBLE PRECISION NOT NULL,
        client_ip TEXT,
        user_agent TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_mcp_http_logs_created_at ON mcp_http_logs (created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_mcp_http_logs_status_code ON mcp_http_logs (status_code)",
]


async def _init_db() -> Optional[AsyncConnectionPool]:
    """Initialise le pool PostgreSQL (psycopg3 / libpq) et crée les tables d'audit."""
    global _db_pool, _db_next_retry_at
    if not DATABASE_URL:
        logger.warning("Aucune variable PostgreSQL valide détectée. Logs écrits en console uniquement.")
        return None

    if _db_pool is not None:
        return _db_pool

    now = time.monotonic()
    if now < _db_next_retry_at:
        return None

    async with _db_lock:
        if _db_pool is not None:
            return _db_pool
        if time.monotonic() < _db_next_retry_at:
            return None

        pool: Optional[AsyncConnectionPool] = None
        try:
            parsed = urlsplit(DATABASE_URL)
            logger.info(
                f"Connexion à PostgreSQL ({parsed.username}@{parsed.hostname}:{parsed.port or 5432}{parsed.path})..."
            )

            # 1. Test unitaire et création des tables avant d'ouvrir le pool
            async with await psycopg.AsyncConnection.connect(DATABASE_URL, connect_timeout=5) as conn:
                for stmt in DB_SCHEMA_STATEMENTS:
                    await conn.execute(stmt)
                await conn.commit()

            # 2. Ouverture du pool asynchrone pour les insertions en arrière-plan
            pool = AsyncConnectionPool(
                conninfo=DATABASE_URL,
                min_size=1,
                max_size=5,
                open=False,
                kwargs={"connect_timeout": 5},
            )
            await pool.open(wait=True, timeout=5.0)
            _db_pool = pool
            _db_next_retry_at = 0.0
            logger.info("Connexion PostgreSQL établie et tables d'audit MCP initialisées.")
        except Exception as exc:
            _db_next_retry_at = time.monotonic() + 60.0
            logger.error(f"Impossible d'initialiser PostgreSQL pour les logs MCP (nouvel essai dans 60s) : {exc}")
            if pool is not None:
                try:
                    await pool.close()
                except Exception:
                    pass
            _db_pool = None

    return _db_pool


async def _close_db() -> None:
    """Attend la fin des écritures en cours et ferme proprement le pool PostgreSQL."""
    global _db_pool
    if _background_tasks:
        await asyncio.gather(*_background_tasks, return_exceptions=True)
    if _db_pool is not None:
        await _db_pool.close()
        _db_pool = None
        logger.info("Pool PostgreSQL fermé.")


def _schedule_db_write(coro) -> None:
    """Planifie une écriture en base sans bloquer la réponse MCP."""
    if not DATABASE_URL:
        coro.close()
        return
    try:
        loop = asyncio.get_running_loop()
        task = loop.create_task(coro)
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)
    except RuntimeError:
        coro.close()


async def _insert_tool_log(
    tool_name: str,
    args: Dict[str, Any],
    dataset_id: Optional[str],
    status: str,
    duration_ms: float,
    response_chars: int,
    est_tokens: int,
    error_message: Optional[str],
) -> None:
    try:
        pool = _db_pool or await _init_db()
        if not pool:
            return
        async with pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO mcp_tool_logs (
                    tool_name, args, dataset_id, status,
                    duration_ms, response_chars, est_tokens, error_message
                )
                VALUES (%s, %s::jsonb, %s, %s, %s, %s, %s, %s)
                """,
                (
                    tool_name,
                    json.dumps(args, ensure_ascii=False, default=str),
                    dataset_id,
                    status,
                    duration_ms,
                    response_chars,
                    est_tokens,
                    error_message,
                ),
            )
    except Exception as exc:
        logger.warning(f"Échec d'insertion PostgreSQL (mcp_tool_logs) : {exc}")


async def _insert_http_log(
    req_id: str,
    method: str,
    path: str,
    status_code: int,
    duration_ms: float,
    client_ip: str,
    user_agent: str,
) -> None:
    try:
        pool = _db_pool or await _init_db()
        if not pool:
            return
        async with pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO mcp_http_logs (
                    req_id, method, path, status_code,
                    duration_ms, client_ip, user_agent
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    req_id,
                    method,
                    path,
                    status_code,
                    duration_ms,
                    client_ip,
                    user_agent,
                ),
            )
    except Exception as exc:
        logger.warning(f"Échec d'insertion PostgreSQL (mcp_http_logs) : {exc}")


# --- TÉLÉMÉTRIE : DÉCORATEUR D'OUTILS & MIDDLEWARE ASGI ---

def _sanitize_args_for_log(raw_args: Dict[str, Any]) -> Dict[str, Any]:
    """Tronque les chaînes très longues avant stockage en base/logs."""
    sanitized: Dict[str, Any] = {}
    for k, v in raw_args.items():
        if isinstance(v, str) and len(v) > 500:
            sanitized[k] = f"{v[:500]}…"
        else:
            sanitized[k] = v
    return sanitized


def track_tool(func):
    """Journalise chaque exécution d'outil MCP en JSON console et dans PostgreSQL."""
    sig = inspect.signature(func)

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        start = time.perf_counter()
        bound = sig.bind_partial(*args, **kwargs)
        bound.apply_defaults()
        status = "success"
        error_msg: Optional[str] = None
        output = ""

        try:
            output = await func(*args, **kwargs)
            if isinstance(output, str) and '"error"' in output[:80]:
                status = "api_error"
                try:
                    parsed_err = json.loads(output)
                    if isinstance(parsed_err, dict):
                        error_msg = str(parsed_err.get("error"))[:500]
                except Exception:
                    pass
            return output
        except Exception as exc:
            status = "exception"
            error_msg = str(exc)[:500]
            raise
        finally:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            out_len = len(output) if isinstance(output, str) else 0
            est_tokens = out_len // 4
            clean_args = _sanitize_args_for_log(dict(bound.arguments))
            dataset_id = clean_args.get("dataset_id") if isinstance(clean_args.get("dataset_id"), str) else None

            audit_logger.info(json.dumps({
                "_msg": f"MCP tool {func.__name__} [{status}] ({duration_ms} ms)",
                "event": "tool_call",
                "tool": func.__name__,
                "args": clean_args,
                "status": status,
                "duration_ms": duration_ms,
                "response_chars": out_len,
                "est_tokens": est_tokens,
                "error": error_msg,
            }, ensure_ascii=False, default=str))

            _schedule_db_write(
                _insert_tool_log(
                    tool_name=func.__name__,
                    args=clean_args,
                    dataset_id=dataset_id,
                    status=status,
                    duration_ms=duration_ms,
                    response_chars=out_len,
                    est_tokens=est_tokens,
                    error_message=error_msg,
                )
            )

    return wrapper


class MCPAccessMiddleware:
    """Middleware ASGI léger compatible streamable-http avec gestion du cycle de vie DB."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            async def lifespan_receive():
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await _init_db()
                return message

            async def lifespan_send(message):
                if message["type"] == "lifespan.shutdown.complete":
                    await _close_db()
                await send(message)

            await self.app(scope, lifespan_receive, lifespan_send)
            return

        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start = time.perf_counter()
        req_id = str(uuid.uuid4())[:8]
        req_headers = dict(scope.get("headers", []))
        user_agent = req_headers.get(b"user-agent", b"unknown").decode("utf-8", errors="replace")[:300]
        forwarded_for = req_headers.get(b"x-forwarded-for", b"").decode("utf-8", errors="replace")
        client_ip = (
            forwarded_for.split(",")[0].strip()
            if forwarded_for
            else (scope["client"][0] if scope.get("client") else "unknown")
        )
        method = scope.get("method", "UNKNOWN")
        path = scope.get("path", "/")
        status_code = 500

        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            audit_logger.info(json.dumps({
                "_msg": f"HTTP {method} {path} -> {status_code} ({duration_ms} ms)",
                "event": "http_request",
                "req_id": req_id,
                "method": method,
                "path": path,
                "status": status_code,
                "duration_ms": duration_ms,
                "client_ip": client_ip,
                "user_agent": user_agent,
            }, ensure_ascii=False))

            _schedule_db_write(
                _insert_http_log(
                    req_id=req_id,
                    method=method,
                    path=path,
                    status_code=status_code,
                    duration_ms=duration_ms,
                    client_ip=client_ip,
                    user_agent=user_agent,
                )
            )


# --- CONFIGURATION API PNDB ---
ODS_API_KEY = _clean_env_val(os.getenv("ODS_API_KEY"))
PNDB_BASE_URL = "https://www.pndb.fr/api/explore/v2.1"

auth_headers = {"Authorization": f"Apikey {ODS_API_KEY}"} if ODS_API_KEY else {}

headers = {
    "User-Agent": "MCP-PNDB-Agent/2.1",
    "Accept": "application/json",
    **auth_headers,
}

if ODS_API_KEY:
    logger.info("Authentification PNDB configurée avec succès (Authorization: Apikey ***).")
else:
    logger.warning("Aucune variable ODS_API_KEY détectée. Accès exécuté en mode anonyme.")

http_client = httpx.AsyncClient(
    base_url=PNDB_BASE_URL,
    timeout=httpx.Timeout(15.0, connect=5.0),
    headers=headers,
)

PORT = int(os.getenv("PORT", "8000"))
MCP_TRANSPORT = _clean_env_val(os.getenv("MCP_TRANSPORT")) or "streamable-http"

mcp = MCPServer("PNDB Biodiversity Catalog Explorer")


# --- UTILITAIRES ---

def _clean_params(raw_params: Dict[str, Any]) -> Dict[str, Any]:
    """Nettoie les paramètres None ou vides."""
    return {k: v for k, v in raw_params.items() if v is not None and v != ""}


def _escape_odsql(value: str) -> str:
    """Échappe les apostrophes pour sécuriser la syntaxe ODSQL."""
    return value.replace("'", "\\'")


class _DescriptionHTMLParser(HTMLParser):
    """Parse le HTML de manière sûre (sans tronquer <) et extrait les liens <a href>."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text_parts: list[str] = []
        self.links: list[Tuple[str, str]] = []
        self._current_href: Optional[str] = None
        self._current_link_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[Tuple[str, Optional[str]]]) -> None:
        tag_l = tag.lower()
        if tag_l in {"p", "br", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"}:
            self.text_parts.append(" ")
        elif tag_l == "a":
            href = (dict(attrs).get("href") or "").strip()
            if href:
                self._current_href = href
                self._current_link_text = []

    def handle_endtag(self, tag: str) -> None:
        tag_l = tag.lower()
        if tag_l in {"p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"}:
            self.text_parts.append(" ")
        elif tag_l == "a" and self._current_href:
            label = re.sub(r"\s+", " ", "".join(self._current_link_text)).strip()
            self.links.append((self._current_href, label))
            self._current_href = None
            self._current_link_text = []

    def handle_data(self, data: str) -> None:
        self.text_parts.append(data)
        if self._current_href is not None:
            self._current_link_text.append(data)


def _parse_description(
    raw_text: Optional[str],
    fallback_ref: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """Retourne (texte_nettoye, source_url) à partir d'une description HTML PNDB."""
    source_url: Optional[str] = fallback_ref.strip() if isinstance(fallback_ref, str) and fallback_ref.strip() else None

    if not raw_text:
        return None, source_url

    parser = _DescriptionHTMLParser()
    parser.feed(raw_text)
    parser.close()

    for href, label in parser.links:
        if "fiche source" in label.lower() or "doi.org" in href.lower():
            source_url = href
            break

    if not source_url and parser.links:
        source_url = parser.links[-1][0]

    cleaned = re.sub(r"\s+", " ", "".join(parser.text_parts)).strip()

    if not source_url and cleaned:
        doi_match = re.search(r"https?://(?:dx\.)?doi\.org/[^\s<>\"']+", cleaned)
        if doi_match:
            source_url = doi_match.group(0).rstrip(".,;)")

    if cleaned:
        cleaned = re.sub(
            r"^[\s:;\-–—.]*Lien vers la fiche source(?:\s*[:\-–—]?\s*https?://\S+)?[\s:;\-–—.]*",
            "",
            cleaned,
            flags=re.IGNORECASE,
        ).strip()
        cleaned = re.sub(
            r"[\s:;\-–—.]*Lien vers la fiche source(?:\s*[:\-–—]?\s*https?://\S+)?[\s:;\-–—.]*$",
            "",
            cleaned,
            flags=re.IGNORECASE,
        ).strip()

    return (cleaned or None), source_url


def _truncate_text(text: Optional[str], max_length: int = 300) -> Optional[str]:
    """Tronque un texte à max_length caractères sur une frontière de mot."""
    if not text or len(text) <= max_length:
        return text
    truncated = text[:max_length].rsplit(" ", 1)[0].rstrip(" ,;:-")
    return f"{truncated}…"


def _extract_records_info(ds_obj: Dict[str, Any], metas: Dict[str, Any]) -> Tuple[Optional[int], Optional[bool]]:
    """Extrait le nombre d'enregistrements (ODS v2.1) et l'indicateur has_records."""
    has_records = ds_obj.get("has_records")
    records_count = metas.get("records_count")
    if records_count is None:
        records_count = ds_obj.get("records_count")
    if records_count is None and has_records is False:
        records_count = 0
    return records_count, has_records


async def _fetch_api(endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Exécute les requêtes HTTP vers le PNDB avec gestion d'erreurs."""
    try:
        clean_p = _clean_params(params or {})
        response = await http_client.get(endpoint, params=clean_p)

        if response.status_code == 401:
            return {"error": "Clé d'API invalide ou expirée (HTTP 401). Vérifiez ODS_API_KEY."}
        if response.status_code == 403:
            return {"error": "Accès refusé (HTTP 403). Droits insuffisants ou quota dépassé."}
        if response.status_code == 404:
            return {"error": "Ressource introuvable sur le catalogue PNDB (HTTP 404).", "code": 404}
        if response.status_code != 200:
            logger.error(f"Erreur API PNDB {response.status_code}: {response.text}")
            return {"error": f"Erreur serveur PNDB (Code HTTP {response.status_code}).", "details": response.text[:200]}

        return response.json()
    except httpx.TimeoutException:
        return {"error": "Timeout : Le serveur du PNDB met trop de temps à répondre."}
    except httpx.RequestError as exc:
        return {"error": f"Erreur réseau lors de la communication avec le PNDB: {str(exc)}"}
    except Exception as exc:
        return {"error": f"Erreur interne du serveur MCP: {str(exc)}"}


# --- OUTILS MCP (TOOLS) ---

@mcp.tool()
@track_tool
async def search_datasets(
    query: Optional[str] = None,
    where: Optional[str] = None,
    order_by: Optional[str] = None,
    limit: int = 10,
    offset: int = 0,
) -> str:
    """
    Recherche des jeux de données dans le catalogue général du PNDB.

    :param query: Termes de recherche (ex: 'chauves-souris', 'bassin versant', 'foret').
    :param where: Filtre ODSQL personnalisé (ex: "publisher:'CNRS' AND default.modified >= '2023'").
    :param order_by: Champ de tri ODSQL (ex: 'modified desc', 'title asc').
    :param limit: Nombre maximum de résultats à retourner (entre 1 et 50).
    :param offset: Décalage de pagination.
    """
    limit_clamped = max(1, min(limit, 50))

    odsql_parts = []
    if query:
        odsql_parts.append(f"search('{_escape_odsql(query)}')")
    if where:
        odsql_parts.append(f"({where})")

    combined_where = " AND ".join(odsql_parts) if odsql_parts else None

    params = {
        "where": combined_where,
        "order_by": order_by,
        "limit": limit_clamped,
        "offset": offset,
    }

    res = await _fetch_api("/catalog/datasets", params)
    if "error" in res:
        return json.dumps(res, ensure_ascii=False)

    clean_datasets = []
    for ds in res.get("results", []):
        metas = (ds.get("metas") or {}).get("default") or {}
        description, source_url = _parse_description(
            metas.get("description"),
            fallback_ref=metas.get("references"),
        )
        records_count, has_records = _extract_records_info(ds, metas)

        clean_datasets.append({
            "dataset_id": ds.get("dataset_id"),
            "titre": metas.get("title"),
            "description": _truncate_text(description, 300),
            "source_url": source_url,
            "editeur": metas.get("publisher"),
            "licence": metas.get("license"),
            "date_modification": metas.get("modified"),
            "nb_enregistrements": records_count,
            "has_records": has_records,
        })

    return json.dumps({
        "total_count": res.get("total_count", 0),
        "returned": len(clean_datasets),
        "datasets": clean_datasets,
    }, ensure_ascii=False, indent=2)


@mcp.tool()
@track_tool
async def get_dataset(dataset_id: str) -> str:
    """
    Récupère la fiche détaillée et le schéma des métadonnées d'un jeu de données.

    :param dataset_id: Identifiant unique du jeu de données PNDB.
    """
    res = await _fetch_api(f"/catalog/datasets/{dataset_id}")
    if "error" in res:
        return json.dumps(res, ensure_ascii=False)

    metas = (res.get("metas") or {}).get("default") or {}
    description, source_url = _parse_description(
        metas.get("description"),
        fallback_ref=metas.get("references"),
    )
    records_count, has_records = _extract_records_info(res, metas)

    fields = [
        {"nom": f.get("name"), "type": f.get("type"), "label": f.get("label")}
        for f in res.get("fields", [])
    ]

    result = {
        "dataset_id": res.get("dataset_id"),
        "titre": metas.get("title"),
        "description": description,
        "source_url": source_url,
        "producteur": metas.get("publisher"),
        "mots_cles": metas.get("keyword"),
        "licence": metas.get("license"),
        "modifie_le": metas.get("modified"),
        "nb_enregistrements": records_count,
        "has_records": has_records,
        "champs_schema": fields,
    }
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
@track_tool
async def query_records(
    dataset_id: str,
    where: Optional[str] = None,
    select: Optional[str] = None,
    group_by: Optional[str] = None,
    order_by: Optional[str] = None,
    limit: int = 10,
    offset: int = 0,
) -> str:
    """
    Interroge les observations et enregistrements scientifiques contenus dans un dataset.

    :param dataset_id: Identifiant du jeu de données.
    :param where: Filtre ODSQL (ex: "annee >= 2020 AND departement:'33'").
    :param select: Projection / agrégation ODSQL (ex: "count(*), avg(temperature)").
    :param group_by: Regroupement ODSQL (ex: "espece, annee").
    :param order_by: Tri ODSQL (ex: "annee desc").
    :param limit: Nombre maximal d'enregistrements (max 100).
    :param offset: Pagination.
    """
    limit_clamped = max(1, min(limit, 100))
    params = {
        "where": where,
        "select": select,
        "group_by": group_by,
        "order_by": order_by,
        "limit": limit_clamped,
        "offset": offset,
    }

    res = await _fetch_api(f"/catalog/datasets/{dataset_id}/records", params)
    if "error" in res:
        return json.dumps(res, ensure_ascii=False)

    records = [rec.get("record", {}).get("fields", {}) for rec in res.get("results", [])]
    return json.dumps({
        "total_count": res.get("total_count", 0),
        "returned": len(records),
        "records": records,
    }, ensure_ascii=False, indent=2)


@mcp.tool()
@track_tool
async def get_record(dataset_id: str, record_id: str) -> str:
    """
    Extrait une observation/enregistrement spécifique par son ID unique.

    :param dataset_id: Identifiant du jeu de données.
    :param record_id: Identifiant unique de l'enregistrement.
    """
    res = await _fetch_api(f"/catalog/datasets/{dataset_id}/records/{record_id}")
    if "error" in res:
        return json.dumps(res, ensure_ascii=False)

    record_data = res.get("record", {})
    return json.dumps({
        "record_id": record_data.get("id"),
        "timestamp": record_data.get("timestamp"),
        "fields": record_data.get("fields", {}),
    }, ensure_ascii=False, indent=2)


@mcp.tool()
@track_tool
async def get_catalog_facets(where: Optional[str] = None) -> str:
    """
    Obtient les facettes globales du catalogue PNDB (répartition par thèmes, producteurs, etc.).
    """
    res = await _fetch_api("/catalog/facets", {"where": where})
    return json.dumps(res, ensure_ascii=False, indent=2)


@mcp.tool()
@track_tool
async def get_dataset_facets(dataset_id: str, where: Optional[str] = None) -> str:
    """
    Obtient la distribution des facettes spécifiques à un jeu de données.
    """
    res = await _fetch_api(f"/catalog/datasets/{dataset_id}/facets", {"where": where})
    return json.dumps(res, ensure_ascii=False, indent=2)


@mcp.tool()
@track_tool
async def list_dataset_exports(dataset_id: str) -> str:
    """
    Liste les formats d'exportation disponibles pour un jeu de données (CSV, GeoJSON, Parquet, etc.).
    """
    res = await _fetch_api(f"/catalog/datasets/{dataset_id}/exports")
    return json.dumps(res, ensure_ascii=False, indent=2)


@mcp.tool()
@track_tool
async def export_dataset(
    dataset_id: str,
    format: str = "json",
    where: Optional[str] = None,
    limit: int = 50,
) -> str:
    """
    Exporte les données d'un dataset dans le format choisi ('json', 'csv', 'geojson', 'parquet').

    :param dataset_id: Identifiant du jeu de données.
    :param format: Format d'exportation souhaité.
    :param where: Filtre ODSQL optionnel.
    :param limit: Limite d'enregistrements exportés.
    """
    params = {"where": where, "limit": min(limit, 500)}

    try:
        response = await http_client.get(
            f"/catalog/datasets/{dataset_id}/exports/{format}",
            params=_clean_params(params),
        )
        if response.status_code != 200:
            return json.dumps(
                {"error": f"Erreur lors de l'exportation (Code HTTP {response.status_code})"},
                ensure_ascii=False,
            )

        content_type = response.headers.get("content-type", "").lower()
        is_binary = format.lower() in {"parquet", "shapefile", "xlsx", "gpkg", "fgb"} or any(
            b_type in content_type for b_type in ("octet-stream", "parquet", "zip", "vnd.openxmlformats")
        )
        if is_binary:
            size_bytes = len(response.content)
            return json.dumps({
                "dataset_id": dataset_id,
                "format": format,
                "type": "binaire",
                "taille_octets": size_bytes,
                "message": (
                    f"Export binaire ({format}, {size_bytes} octets) généré avec succès. "
                    "Utilisez 'json', 'csv' ou 'geojson' pour une lecture directe du contenu."
                ),
                "url_export": str(response.request.url),
            }, ensure_ascii=False, indent=2)

        content = response.text
        if len(content) > 10000:
            return content[:10000] + "\n... [Contenu d'export tronqué pour préserver la fenêtre de contexte]"
        return content
    except Exception as exc:
        return json.dumps({"error": f"Échec de la requête d'exportation: {str(exc)}"}, ensure_ascii=False)


@mcp.tool()
@track_tool
async def list_attachments(dataset_id: str) -> str:
    """
    Liste l'ensemble des fichiers joints et documents associés (rapports EML, annexes PDF).
    """
    res = await _fetch_api(f"/catalog/datasets/{dataset_id}/attachments")
    return json.dumps(res, ensure_ascii=False, indent=2)


@mcp.tool()
@track_tool
async def get_attachment_info(dataset_id: str, attachment_id: str) -> str:
    """
    Obtient les métadonnées et le lien direct d'une pièce jointe.
    """
    res = await _fetch_api(f"/catalog/datasets/{dataset_id}/attachments/{attachment_id}")
    return json.dumps(res, ensure_ascii=False, indent=2)


# --- RESSOURCES ET PROMPTS ---

@mcp.resource("pndb://catalog/schema")
async def get_catalog_schema() -> str:
    """Ressource MCP décrivant la structure générale de l'API PNDB."""
    return json.dumps({
        "protocol": "Opendatasoft Explore API v2.1",
        "platform": "Pôle National de Données de Biodiversité (PNDB)",
        "query_language": "ODSQL",
        "auth_header": "Authorization: Apikey <ODS_API_KEY>",
    }, ensure_ascii=False, indent=2)


@mcp.prompt()
def analyze_biodiversity_dataset(dataset_id: str) -> str:
    """Prompt type pour guider le LLM dans l'évaluation de la qualité des données PNDB."""
    return f"""Vous êtes un expert en écologie et en science des données FAIR.
Veuillez utiliser l'outil `get_dataset(dataset_id='{dataset_id}')` pour inspecter ce jeu de données PNDB.
Rédigez ensuite une synthèse contenant :
1. Les objectifs scientifiques et taxonomiques du jeu de données.
2. La licence et les conditions de réutilisation.
3. Les champs principaux disponibles et les recommandations d'usage.
"""


if __name__ == "__main__":
    logger.info(f"Démarrage du serveur MCP PNDB sur 0.0.0.0:{PORT} (transport={MCP_TRANSPORT})")

    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False
    )

    if MCP_TRANSPORT == "sse":
        raw_app = mcp.sse_app(transport_security=security)
    else:
        raw_app = mcp.streamable_http_app(transport_security=security)

    app = MCPAccessMiddleware(raw_app)
    uvicorn.run(app, host="0.0.0.0", port=PORT, access_log=False)