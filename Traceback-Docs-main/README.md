# Traceback API Documentation

Main URL: `https://traceback.sh/api/<route>`

## Endpoints

### 1. Database Lookup

| **Endpoint** | **Method** | **Description** |
|--------------|------------|-----------------|
| `/v1/dblookups` | POST | Perform a database lookup for a specific field and query. |

**Headers:**
- `X-API-KEY`: The API key for authentication.

**Request Body:**
```json
{
    "query": "example@example.com",
    "field": "email",
    "limit": 100,
    "use_wildcard": false,
    "use_regex": false
}
```

**Valid Fields:** username, email, password, url, ip_address, domain, country, discord, phone

### 2. Realtime Lookup

| **Endpoint** | **Method** | **Description** |
|--------------|------------|-----------------|
| `/v1/realtime` | POST | Perform a realtime lookup for a specific field and query using custom modules and CSINT module data from nosint.org. |

**Headers:**
- `X-API-KEY`: The API key for authentication.

**Request Body:**
```json
{
    "query": "example@example.com",
    "field": "email"
}
```

**Valid Fields:** username, email, ip_address, domain, name, minecraft

### 3. IntelX Lookup

| **Endpoint** | **Method** | **Description** |
|--------------|------------|-----------------|
| `/v1/intelx` | POST | Perform an IntelX lookup for an email or system ID. |

**Headers:**
- `X-API-KEY`: The API key for authentication.

**Request Body:**
```json
{
    "query": "example@example.com",
    "field": "email"
}
```

**Valid Fields:** email, systemid
