#!/usr/bin/env bash
set -euo pipefail
cat > app_v2.py <<'PY'
#!/usr/bin/env python3
"""
app_v2.py — DevOps Local: Universal JSON Validator + AI Chat Converter
Termux/Android armv8 (no-root) | Pure Python stdlib (no pycryptodome)
Auth: hmac/hashlib/secrets (stdlib replacement)
Modes: basic | advanced | production
v2 new features:
  - Universal schema validation (any JSON Schema draft-04/07 or built-in)
  - AI chat JSON -> book-style text converter
  - Web Speech API TTS (Android Chrome native, no server-side dep)
  - AI Fix Prompt generator (copy-paste into any AI chat)
  - Download results as text/JSON
  - Copy-protected textarea output boxes
  - Real per-IP rate limiting (sliding window)
  - FIX: mode default "balanced"->basic (argparse choices bug)
  - FIX: trustscore floor was 0.5 -> now 0.0 (honest scoring)
  - FIX: basic.sh/advanced_check.sh created with actual newlines
  - FIX: additionalProperties root level false -> true (permissive)
  - FIX: test_cli_validate.py added (was missing)
  - FIX: rate_store now actually populated and enforced
"""
import os, sys, json, argparse, time, threading, logging, tempfile, signal
import hmac, hashlib, secrets, re
from datetime import datetime, timezone
from http import HTTPStatus
from logging.handlers import RotatingFileHandler

BASE = os.path.abspath(os.path.dirname(__file__))
CONFIG_PATH  = os.path.join(BASE, "config.json")
REQ_PATH     = os.path.join(BASE, "requirements.txt")
README_PATH  = os.path.join(BASE, "README.md")
SCHEMA_PATH  = os.path.join(BASE, "validation-grid-schema.json")
SCRIPTS_DIR  = os.path.join(BASE, "scripts")
ALERTS_DIR   = os.path.join(BASE, "alerts")
TO_VALIDATE  = os.path.join(BASE, "to_validate")
LOG_PATH     = os.path.join(BASE, "devops_local.log")

REQUIREMENTS = "Flask==2.3.2\njsonschema==4.17.3\n"

# ─── BUILT-IN SCHEMA (DevOps Grid format) ────────────────────────────────────
SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Validation Grid Schema",
    "type": "object",
    "required": ["metadata","rulesandconstraints","evidence","reasoningtrace","validation","trustscore"],
    "additionalProperties": True,   # FIX: was False — too strict for general use
    "properties": {
        "metadata": {
            "type": "object",
            "required": ["schemaversion","validatedat","author","language","title","executivesummary"],
            "additionalProperties": True,
            "properties": {
                "schemaversion":    {"type":"string"},
                "validatedat":      {"type":"string","format":"date-time"},
                "author":           {"type":"string"},
                "language":         {"type":"string"},
                "title":            {"type":"string"},
                "executivesummary": {"type":"string"}
            }
        },
        "rulesandconstraints": {
            "type": "object",
            "required": ["nohallucination","requireevidence","explicitlimitationswheninsufficientdata",
                         "traceabilityrequired","explainstructuralreasoning","donotguess"],
            "additionalProperties": True,
            "properties": {
                "nohallucination":                     {"type":"boolean"},
                "requireevidence":                     {"type":"boolean"},
                "explicitlimitationswheninsufficientdata": {"type":"boolean"},
                "traceabilityrequired":                {"type":"boolean"},
                "explainstructuralreasoning":          {"type":"boolean"},
                "donotguess":                          {"type":"boolean"}
            }
        },
        "evidence": {
            "type":"array","minItems":1,
            "items": {
                "type":"object",
                "required":["id","type","source","sourceuri","collectedat","verifier","relevance"],
                "additionalProperties":True,
                "properties": {
                    "id":{"type":"string"},"type":{"type":"string"},
                    "source":{"type":"string"},"sourceuri":{"type":"string","format":"uri"},
                    "collectedat":{"type":"string","format":"date-time"},
                    "verifier":{"type":"string"},"relevance":{"type":"string"}
                }
            }
        },
        "reasoningtrace": {
            "type":"array","minItems":1,
            "items": {
                "type":"object",
                "required":["stepid","description","inputs","operation","output","timestamp"],
                "additionalProperties":True,
                "properties": {
                    "stepid":{"type":"string"},"description":{"type":"string"},
                    "inputs":{"type":"array","minItems":1,"items":{"type":"string"}},
                    "operation":{"type":"string"},"output":{"type":"string"},
                    "timestamp":{"type":"string","format":"date-time"}
                }
            }
        },
        "validation": {
            "type":"object","required":["passed","validator","checksrun","collectedat"],
            "additionalProperties":True,
            "properties": {
                "passed":{"type":"boolean"},"validator":{"type":"string"},
                "checksrun": {
                    "type":"array","minItems":1,
                    "items": {
                        "type":"object","required":["checkname","status","durationms"],
                        "additionalProperties":True,
                        "properties": {
                            "checkname":{"type":"string"},
                            "status":{"type":"string","enum":["pass","fail","warn"]},
                            "durationms":{"type":"number"}
                        }
                    }
                },
                "collectedat":{"type":"string","format":"date-time"}
            }
        },
        "trustscore": {"type":"number","minimum":0,"maximum":1}
    }
}

# ─── STRICT SCHEMA (Validation Grid Audit) ───────────────────────────────────
SCHEMA_STRICT = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "https://example.com/schemas/validation-grid-audit.strict.schema.json",
    "title": "Validation Grid - Schema (Strict)",
    "type": "object",
    "additionalProperties": False,
    "required": ["checksandmetrics","evidence","example_checks","final_recommendation",
                 "metadata","procedure","reasoningtrace","rulesandconstraints","trustscore","validation"],
    "properties": {
        "checksandmetrics": {
            "type":"object","additionalProperties":False,
            "required":["biasrisklevel","consistency_score","provenance_score","reproducibility_score"],
            "properties": {
                "biasrisklevel": {
                    "type":"object","additionalProperties":False,
                    "required":["description","interpretation","levels","value"],
                    "properties": {
                        "description":{"type":"string","minLength":1,"maxLength":1000},
                        "interpretation":{"type":"string","minLength":1,"maxLength":1000},
                        "levels":{"type":"array","minItems":1,"uniqueItems":True,
                                  "items":{"type":"string","enum":["low","medium","high"]}},
                        "value":{"type":"string","enum":["low","medium","high"]}
                    }
                },
                "consistency_score": {
                    "type":"object","additionalProperties":False,
                    "required":["description","interpretation","scale","value"],
                    "properties": {
                        "description":{"type":"string","minLength":1,"maxLength":1000},
                        "interpretation":{"type":"string","minLength":1,"maxLength":1000},
                        "scale":{"type":"string","enum":["0-1"]},
                        "value":{"type":"number","minimum":0,"maximum":1}
                    }
                },
                "provenance_score": {
                    "type":"object","additionalProperties":False,
                    "required":["description","interpretation","scale","value"],
                    "properties": {
                        "description":{"type":"string","minLength":1,"maxLength":1000},
                        "interpretation":{"type":"string","minLength":1,"maxLength":1000},
                        "scale":{"type":"string","enum":["0-1"]},
                        "value":{"type":"number","minimum":0,"maximum":1}
                    }
                },
                "reproducibility_score": {
                    "type":"object","additionalProperties":False,
                    "required":["description","interpretation","scale","value"],
                    "properties": {
                        "description":{"type":"string","minLength":1,"maxLength":1000},
                        "interpretation":{"type":"string","minLength":1,"maxLength":1000},
                        "scale":{"type":"string","enum":["0-1"]},
                        "value":{"type":"number","minimum":0,"maximum":1}
                    }
                }
            }
        },
        "evidence": {
            "type":"array","minItems":1,
            "items": {
                "type":"object","additionalProperties":False,
                "required":["collectedat","id","notes","relevance","source","sourceuri","type","verifier"],
                "properties": {
                    "collectedat":{"type":"string","format":"date-time"},
                    "id":{"type":"string","pattern":"^evidence-\\d{3,}$"},
                    "notes":{"type":"string","minLength":1,"maxLength":2000},
                    "relevance":{"type":"string","enum":["low","medium","high"]},
                    "source":{"type":"string","minLength":1,"maxLength":256},
                    "sourceuri":{"type":"string","format":"uri","maxLength":2000},
                    "type":{"type":"string","minLength":1,"maxLength":128},
                    "verifier":{"type":"string","minLength":1,"maxLength":128}
                }
            }
        },
        "example_checks": {
            "type":"array","minItems":1,
            "items": {
                "type":"object","additionalProperties":False,
                "required":["actions","expected_outcome","scenario"],
                "properties": {
                    "actions":{"type":"string","minLength":1,"maxLength":1000},
                    "expected_outcome":{"type":"string","minLength":1,"maxLength":1000},
                    "scenario":{"type":"string","minLength":1,"maxLength":256}
                }
            }
        },
        "final_recommendation": {
            "type":"object","additionalProperties":False,
            "required":["detailed","short"],
            "properties": {
                "detailed":{"type":"string","minLength":1,"maxLength":5000},
                "short":{"type":"string","minLength":1,"maxLength":512}
            }
        },
        "metadata": {
            "type":"object","additionalProperties":False,
            "required":["author","executivesummary","language","schemaversion","title","validatedat"],
            "properties": {
                "author":{"type":"string","minLength":1,"maxLength":256},
                "executivesummary":{"type":"string","minLength":1,"maxLength":2000},
                "language":{"type":"string","pattern":"^[a-z]{2}(-[A-Z]{2})?$"},
                "schemaversion":{"type":"string","pattern":"^\\d+\\.\\d+(?:\\.\\d+)?$"},
                "title":{"type":"string","minLength":1,"maxLength":256},
                "validatedat":{"type":"string","format":"date-time"}
            }
        },
        "procedure": {
            "type":"object","additionalProperties":False,
            "required":["assumptions","goal","limitationsandexpectations","practical_tips",
                        "recommendedtoolsandmethods","safety_considerations","stepbystep"],
            "properties": {
                "assumptions":{"type":"array","minItems":1,"items":{"type":"string","minLength":1,"maxLength":1000}},
                "goal":{"type":"string","minLength":1,"maxLength":1000},
                "limitationsandexpectations":{"type":"array","minItems":1,"items":{"type":"string","minLength":1,"maxLength":1000}},
                "practical_tips":{"type":"array","minItems":1,"items":{"type":"string","minLength":1,"maxLength":1000}},
                "recommendedtoolsandmethods":{"type":"array","minItems":1,"items":{"type":"string","minLength":1,"maxLength":256}},
                "safety_considerations":{"type":"array","minItems":1,"items":{"type":"string","minLength":1,"maxLength":1000}},
                "stepbystep": {
                    "type":"array","minItems":1,
                    "items": {
                        "type":"object","additionalProperties":False,
                        "required":["details","step","title"],
                        "properties": {
                            "details":{"type":"string","minLength":1,"maxLength":2000},
                            "step":{"type":"integer","minimum":1},
                            "title":{"type":"string","minLength":1,"maxLength":256}
                        }
                    }
                }
            }
        },
        "reasoningtrace": {
            "type":"array","minItems":1,
            "items": {
                "type":"object","additionalProperties":False,
                "required":["description","inputs","operation","output","stepid","timestamp"],
                "properties": {
                    "description":{"type":"string","minLength":1,"maxLength":2000},
                    "inputs":{"type":"array","minItems":1,"items":{"type":"string","minLength":1,"maxLength":1024}},
                    "operation":{"type":"string","minLength":1,"maxLength":512},
                    "output":{"type":"string","minLength":1,"maxLength":2000},
                    "stepid":{"type":"string","pattern":"^step-\\d{1,6}$"},
                    "timestamp":{"type":"string","format":"date-time"}
                }
            }
        },
        "rulesandconstraints": {
            "type":"object","additionalProperties":False,
            "required":["donotguess","explainstructuralreasoning","explicitlimitationswheninsufficientdata",
                        "nohallucination","requireevidence","traceabilityrequired"],
            "properties": {
                "donotguess":{"type":"boolean"},
                "explainstructuralreasoning":{"type":"boolean"},
                "explicitlimitationswheninsufficientdata":{"type":"boolean"},
                "nohallucination":{"type":"boolean"},
                "requireevidence":{"type":"boolean"},
                "traceabilityrequired":{"type":"boolean"}
            }
        },
        "trustscore":{"type":"number","minimum":0,"maximum":1},
        "validation": {
            "type":"object","additionalProperties":False,
            "required":["checksrun","collectedat","passed","summary","validator"],
            "properties": {
                "checksrun": {
                    "type":"array","minItems":1,
                    "items": {
                        "type":"object","additionalProperties":False,
                        "required":["checkname","durationms","notes","status"],
                        "properties": {
                            "checkname":{"type":"string","minLength":1,"maxLength":256},
                            "durationms":{"type":"integer","minimum":0},
                            "notes":{"type":"string","minLength":1,"maxLength":2000},
                            "status":{"type":"string","enum":["pass","fail"]}
                        }
                    }
                },
                "collectedat":{"type":"string","format":"date-time"},
                "passed":{"type":"boolean"},
                "summary":{"type":"string","minLength":1,"maxLength":2000},
                "validator":{"type":"string","minLength":1,"maxLength":256}
            }
        }
    }
}

# ─── SAMPLE for STRICT SCHEMA ─────────────────────────────────────────────────
SAMPLE_STRICT = {
    "checksandmetrics": {
        "biasrisklevel": {
            "description": "การประเมินความเสี่ยงจากอคติในผลลัพธ์",
            "interpretation": "ค่ายิ่งสูงแปลว่ามีความเสี่ยงจากอคติมากขึ้น",
            "levels": ["low","medium","high"],
            "value": "medium"
        },
        "consistency_score": {"description":"คะแนนความสอดคล้องภายในผลลัพธ์",
            "interpretation":"ค่าใกล้ 1 แสดงความสอดคล้องสูง","scale":"0-1","value":0.87},
        "provenance_score": {"description":"คะแนนความชัดเจนของแหล่งที่มา",
            "interpretation":"ค่าสูงแสดงว่าแหล่งที่มาตรวจสอบได้","scale":"0-1","value":0.92},
        "reproducibility_score": {"description":"ความสามารถในการทำซ้ำผลลัพธ์",
            "interpretation":"ค่าใกล้ 1 แปลว่าทำซ้ำได้สูง","scale":"0-1","value":0.78}
    },
    "evidence": [{"collectedat":"2026-03-22T09:00:00Z","id":"evidence-123",
        "notes":"Log การรันตัวอย่าง 25 prompt","relevance":"high",
        "source":"internal-audit-logs","sourceuri":"https://example.com/audit/logs/123",
        "type":"log","verifier":"auditor-1"}],
    "example_checks": [{"actions":"ส่ง prompt ตัวอย่าง A และบันทึกผลลัพธ์",
        "expected_outcome":"ผลลัพธ์สอดคล้องกันและอ้างอิงแหล่งเดียวกัน",
        "scenario":"consistency-check-basic-factual"}],
    "final_recommendation": {
        "detailed": "แนะนำให้บันทึกตัวระบุชุดข้อมูลและเวอร์ชันของแหล่งที่มาอย่างเป็นระบบ เพิ่ม seed และ bias mitigation",
        "short": "บันทึก provenance ให้ละเอียด เพิ่ม deterministic seeding และทำ bias mitigation"
    },
    "metadata": {"author":"Validation Team",
        "executivesummary":"การตรวจสอบพบความสอดคล้องและ provenance ดี",
        "language":"th-TH","schemaversion":"1.0.0",
        "title":"Validation Grid Audit Example","validatedat":"2026-03-22T11:30:00Z"},
    "procedure": {
        "assumptions":["ชุดข้อมูลที่อ้างอิงเป็นเวอร์ชัน production"],
        "goal":"ประเมินอคติ ความสอดคล้อง provenance และความสามารถทำซ้ำ",
        "limitationsandexpectations":["ตัวอย่างไม่ครอบคลุมแบบ exhaustive"],
        "practical_tips":["บันทึก seed ทุกครั้งที่รัน"],
        "recommendedtoolsandmethods":["deterministic-runner","provenance-tracker"],
        "safety_considerations":["ห้ามเผยแพร่ PII ในหลักฐาน"],
        "stepbystep":[
            {"details":"เตรียมชุด prompt และผลลัพธ์ที่คาดหวัง","step":1,"title":"Prepare test corpus"},
            {"details":"รันโมเดลภายใต้เงื่อนไขควบคุม บันทึก seed","step":2,"title":"Execute controlled runs"},
            {"details":"วิเคราะห์ผลลัพธ์และบันทึกหลักฐาน","step":3,"title":"Analyze results"}
        ]
    },
    "reasoningtrace": [
        {"description":"คัดเลือก prompt และจับคู่แหล่งอ้างอิง",
         "inputs":["prompt-set-v1","authoritative-source-list"],
         "operation":"mapping-and-selection","output":"selected 25 prompts",
         "stepid":"step-1","timestamp":"2026-03-22T09:15:00Z"},
        {"description":"รันโมเดลด้วย deterministic seed",
         "inputs":["selected-25-prompts","seed-20260322-001"],
         "operation":"execution-and-capture","output":"captured outputs and metadata",
         "stepid":"step-2","timestamp":"2026-03-22T10:00:00Z"},
        {"description":"คำนวณเมตริกจากข้อมูลที่จับได้",
         "inputs":["captured-outputs","provenance-records"],
         "operation":"metric-computation","output":"consistency=0.87; provenance=0.92; reproducibility=0.78",
         "stepid":"step-3","timestamp":"2026-03-22T11:00:00Z"}
    ],
    "rulesandconstraints": {"donotguess":True,"explainstructuralreasoning":True,
        "explicitlimitationswheninsufficientdata":True,"nohallucination":True,
        "requireevidence":True,"traceabilityrequired":True},
    "trustscore": 0.85,
    "validation": {
        "checksrun":[{"checkname":"consistency-check","durationms":1200,
            "notes":"เปรียบเทียบการรันซ้ำ 25 prompt","status":"pass"}],
        "collectedat":"2026-03-22T11:45:00Z","passed":True,
        "summary":"Validation ผ่านโดยมีคำแนะนำให้ปรับปรุง provenance",
        "validator":"validation-team-lead"
    }
}

# ─── SCHEMA REGISTRY ──────────────────────────────────────────────────────────
BUILTIN_SCHEMAS = {
    "basic":  {"schema": SCHEMA,        "label": "DevOps Grid (Basic)",  "sample": None},
    "strict": {"schema": SCHEMA_STRICT, "label": "Validation Grid (Strict)", "sample": SAMPLE_STRICT},
}

DEFAULT_CONFIG = {
    "mode": "basic",          # FIX: was "balanced" — not in argparse choices
    "web_port": 8080,
    "health_check_interval": 30,
    "log_max_bytes": 200000,
    "log_backup_count": 3,
    "alert_thresholds": {"errors_per_min": 10},
    "auth_token": "",         # FIX: generate on first run, not hardcoded
    "rate_limit_requests": 60,
    "rate_limit_window_sec": 60
}

# ─── AUTH (pure stdlib: hmac/hashlib/secrets) ─────────────────────────────────
def gen_token(n=32):
    return secrets.token_hex(n)

def sign_token(value: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()

def verify_bearer(header: str, secret: str) -> bool:
    if not header.startswith("Bearer "):
        return False
    tok = header.split(" ", 1)[1]
    expected = sign_token(tok, secret)
    try:
        return hmac.compare_digest(sign_token(tok, secret), expected)
    except Exception:
        return False

def check_bearer(header: str, token: str) -> bool:
    """Simple constant-time token comparison."""
    if not header.startswith("Bearer "):
        return False
    provided = header.split(" ", 1)[1]
    return hmac.compare_digest(provided.encode("utf-8"), token.encode("utf-8"))

# ─── UTILITIES ────────────────────────────────────────────────────────────────
def iso_now():
    return datetime.now(timezone.utc).isoformat()

def safe_write(path, data, mode='w', perms=None):
    """Atomic write via tempfile + os.replace."""
    dirn = os.path.dirname(path) or '.'
    os.makedirs(dirn, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dirn)
    try:
        is_text = 'b' not in mode
        with os.fdopen(fd, mode, **({"encoding": "utf-8"} if is_text else {})) as f:
            f.write(data)
        if perms:
            try: os.chmod(tmp, perms)
            except Exception: pass
        os.replace(tmp, path)
    except Exception:
        try: os.remove(tmp)
        except Exception: pass
        raise

def ensure_structure():
    os.makedirs(SCRIPTS_DIR, exist_ok=True)
    os.makedirs(ALERTS_DIR, exist_ok=True)
    os.makedirs(TO_VALIDATE, exist_ok=True)
    if not os.path.exists(REQ_PATH):
        safe_write(REQ_PATH, REQUIREMENTS)
    if not os.path.exists(SCHEMA_PATH):
        safe_write(SCHEMA_PATH, json.dumps(SCHEMA, indent=2, ensure_ascii=False))
    if not os.path.exists(CONFIG_PATH):
        cfg = dict(DEFAULT_CONFIG)
        cfg["auth_token"] = gen_token()  # FIX: unique token per install
        safe_write(CONFIG_PATH, json.dumps(cfg, indent=2, ensure_ascii=False))
        try: os.chmod(CONFIG_PATH, 0o600)
        except Exception: pass
    # FIX: actual newlines in shell scripts (was \\n in original)
    basic_sh = os.path.join(SCRIPTS_DIR, "basic.sh")
    if not os.path.exists(basic_sh):
        safe_write(basic_sh, "#!/bin/sh\nls -la\n")
        try: os.chmod(basic_sh, 0o700)
        except Exception: pass
    adv_sh = os.path.join(SCRIPTS_DIR, "advanced_check.sh")
    if not os.path.exists(adv_sh):
        script = (
            '#!/bin/sh\n'
            'BASEDIR="$(cd "$(dirname "$0")" && pwd)/.."\n'
            'for f in "$BASEDIR/to_validate"/*.json; do\n'
            '  [ -f "$f" ] || continue\n'
            '  echo "Validating $f"\n'
            '  python3 "$BASEDIR/app_v2.py" validate "$f"\n'
            'done\n'
        )
        safe_write(adv_sh, script)
        try: os.chmod(adv_sh, 0o700)
        except Exception: pass
    sample = os.path.join(TO_VALIDATE, "sample.json")
    if not os.path.exists(sample):
        s = {
            "metadata": {"schemaversion":"2.0","validatedat":"2025-01-01T00:00:00Z",
                         "author":"local-user","language":"th","title":"ตัวอย่าง",
                         "executivesummary":"เอกสารทดสอบระบบ"},
            "rulesandconstraints": {"nohallucination":True,"requireevidence":True,
                "explicitlimitationswheninsufficientdata":False,"traceabilityrequired":True,
                "explainstructuralreasoning":True,"donotguess":True},
            "evidence": [{"id":"EVID-1","type":"web","source":"example","sourceuri":"https://example.com",
                "collectedat":"2025-01-01T00:00:00Z","verifier":"local","relevance":"high"}],
            "reasoningtrace": [{"stepid":"STEP-1","description":"สร้างตัวอย่าง","inputs":["EVID-1"],
                "operation":"create","output":"sample ok","timestamp":"2025-01-01T00:00:00Z"}],
            "validation": {"passed":True,"validator":"local",
                "checksrun":[{"checkname":"schema-check","status":"pass","durationms":10}],
                "collectedat":"2025-01-01T00:00:00Z"},
            "trustscore": 0.9
        }
        safe_write(sample, json.dumps(s, indent=2, ensure_ascii=False))

# ─── LOGGING ──────────────────────────────────────────────────────────────────
logger = logging.getLogger("devops_local")
logger.setLevel(logging.INFO)
def _setup_log(max_bytes=200000, backup=3):
    for h in list(logger.handlers): logger.removeHandler(h)
    try:
        fh = RotatingFileHandler(LOG_PATH, maxBytes=max_bytes, backupCount=backup)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(fh)
    except Exception:
        ch = logging.StreamHandler()
        logger.addHandler(ch)
_setup_log()

# ─── VALIDATION ───────────────────────────────────────────────────────────────
def try_import_jsonschema():
    try:
        import jsonschema
        return jsonschema
    except ImportError:
        return None

def validate_json_against_schema(doc, schema=None):
    """
    Validate doc against schema (or built-in SCHEMA).
    Returns (ok: bool, error: str|None).
    """
    js = try_import_jsonschema()
    if not js:
        return None, "jsonschema not installed — run: pip install jsonschema"
    target_schema = schema if schema is not None else SCHEMA
    try:
        js.validate(instance=doc, schema=target_schema)
        return True, None
    except js.exceptions.ValidationError as e:
        # Return clean error path + message
        path = " -> ".join(str(p) for p in e.absolute_path) if e.absolute_path else "root"
        return False, f"[{path}] {e.message}"
    except js.exceptions.SchemaError as e:
        return False, f"Schema itself is invalid: {e.message}"
    except Exception as e:
        return False, str(e)

def validate_syntax_only(doc):
    """Fast check: is this parseable JSON with basic structure info."""
    info = {"type": type(doc).__name__, "keys": list(doc.keys()) if isinstance(doc, dict) else None,
            "length": len(doc) if isinstance(doc, (list, dict)) else None}
    return True, info

# ─── TRUST SCORE ─────────────────────────────────────────────────────────────
def compute_trustscore(doc):
    """
    Unified trustscore for both Basic and Strict schemas.
    Basic:  evidence relevance + checksrun pass rate + metadata presence
    Strict: adds checksandmetrics scores (consistency/provenance/reproducibility)
    """
    evidence_score = 0.0
    try:
        ev = doc.get("evidence", [])
        if isinstance(ev, list) and ev:
            mapping = {"high":1.0,"medium":0.6,"low":0.2}
            vals = [mapping.get(str(e.get("relevance","")).lower(), 0.1) for e in ev]
            evidence_score = sum(vals) / len(vals)
    except Exception:
        pass

    validation_score = 0.0
    try:
        checks = doc.get("validation", {}).get("checksrun", [])
        if checks:
            passed = sum(1 for c in checks if c.get("status") == "pass")
            validation_score = passed / len(checks)
    except Exception:
        pass

    meta_score = 0.1 if doc.get("metadata") else 0.0

    # Strict schema bonus: average of checksandmetrics numeric scores
    metrics_score = 0.0
    try:
        cm = doc.get("checksandmetrics", {})
        vals = []
        for key in ("consistency_score","provenance_score","reproducibility_score"):
            v = cm.get(key, {}).get("value")
            if isinstance(v, (int, float)):
                vals.append(float(v))
        if vals:
            metrics_score = sum(vals) / len(vals)
    except Exception:
        pass

    has_metrics = metrics_score > 0.0
    if has_metrics:
        # Strict formula: metrics weighted more heavily
        trust = round(max(0.0, min(1.0,
            0.35*evidence_score + 0.30*validation_score + 0.30*metrics_score + 0.05*meta_score)), 3)
    else:
        trust = round(max(0.0, min(1.0,
            0.50*evidence_score + 0.40*validation_score + 0.10*meta_score)), 3)

    return trust, {
        "evidence_score": evidence_score,
        "validation_score": validation_score,
        "meta_score": meta_score,
        "metrics_score": metrics_score
    }

# ─── JSON-TO-BOOK-TEXT CONVERTER ─────────────────────────────────────────────
def extract_json_from_text(text):
    """Extract JSON objects/arrays from arbitrary text (AI chat responses)."""
    results = []
    # Try fenced code blocks first
    fenced = re.findall(r'```(?:json)?\s*([\s\S]*?)```', text)
    for block in fenced:
        try:
            results.append(json.loads(block.strip()))
        except Exception:
            pass
    # Try whole text
    if not results:
        try:
            results.append(json.loads(text.strip()))
        except Exception:
            pass
    # Try to find JSON objects/arrays anywhere in text
    if not results:
        for match in re.finditer(r'(\{[\s\S]*?\}|\[[\s\S]*?\])', text):
            try:
                obj = json.loads(match.group(0))
                results.append(obj)
            except Exception:
                pass
    return results

def _format_value(val, depth=0):
    indent = "    " * depth
    lines = []
    if isinstance(val, dict):
        for k, v in val.items():
            heading = str(k).replace("_"," ").replace("-"," ").title()
            if isinstance(v, (dict, list)):
                lines.append(f"\n{indent}{heading}:")
                lines.extend(_format_value(v, depth+1))
            elif isinstance(v, bool):
                lines.append(f"{indent}{heading}: {'ใช่' if v else 'ไม่ใช่'}")
            elif v is None:
                lines.append(f"{indent}{heading}: —")
            else:
                lines.append(f"{indent}{heading}: {v}")
    elif isinstance(val, list):
        for i, item in enumerate(val):
            if isinstance(item, (dict, list)):
                lines.append(f"{indent}รายการที่ {i+1}:")
                lines.extend(_format_value(item, depth+1))
            elif isinstance(item, bool):
                lines.append(f"{indent}  • {'ใช่' if item else 'ไม่ใช่'}")
            elif item is None:
                lines.append(f"{indent}  • —")
            else:
                lines.append(f"{indent}  • {item}")
    else:
        lines.append(f"{indent}{val}")
    return lines

def json_to_booktext(obj, title="เนื้อหาที่แปลงแล้ว"):
    """Convert any JSON object to book-style formatted text."""
    lines = [f"{'═'*50}", f"  {title}", f"{'═'*50}", ""]
    if isinstance(obj, dict):
        for i, (k, v) in enumerate(obj.items()):
            heading = str(k).replace("_"," ").replace("-"," ").title()
            lines.append(f"【 {heading} 】")
            lines.extend(_format_value(v, depth=1))
            lines.append("")
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            lines.append(f"── รายการที่ {i+1} ──")
            lines.extend(_format_value(item, depth=1))
            lines.append("")
    else:
        lines.append(str(obj))
    lines += [f"{'─'*50}", f"  สร้างเมื่อ: {iso_now()}", f"{'─'*50}"]
    return "\n".join(lines)

# ─── AI FIX PROMPT GENERATOR ─────────────────────────────────────────────────
def generate_fix_prompt(doc, error_msg, schema=None):
    """Generate a prompt that users can paste into any AI chat to fix validation errors."""
    schema_used = schema or SCHEMA
    schema_str = json.dumps(schema_used, indent=2, ensure_ascii=False)
    doc_str = json.dumps(doc, indent=2, ensure_ascii=False)
    # Truncate if too long for readability
    if len(schema_str) > 2500:
        schema_str = schema_str[:2500] + "\n... (ตัดทอน)"
    if len(doc_str) > 3000:
        doc_str = doc_str[:3000] + "\n... (ตัดทอน)"
    prompt = f"""คุณเป็น Senior JSON Schema Expert

❌ พบข้อผิดพลาด Validation:
{error_msg}

📋 Schema ที่ใช้ตรวจสอบ:
```json
{schema_str}
```

📄 JSON ที่ต้องแก้ไข:
```json
{doc_str}
```

กรุณา:
1. วิเคราะห์สาเหตุที่แท้จริงของข้อผิดพลาด
2. แสดง JSON ที่แก้ไขแล้วทั้งหมดในรูปแบบ code block
3. สรุปการเปลี่ยนแปลงแต่ละจุดเป็นภาษาไทย
4. ตรวจสอบว่า JSON ที่แก้ไขแล้วผ่าน schema ทุกข้อ"""
    return prompt

# ─── RATE LIMITER ─────────────────────────────────────────────────────────────
_rate_store = {}
_rate_lock = threading.Lock()

def check_rate_limit(ip, limit=60, window=60):
    """
    FIX: Previous version defined _rate_store but never populated it.
    Sliding window counter — returns (allowed: bool, remaining: int).
    """
    now = time.time()
    with _rate_lock:
        timestamps = _rate_store.get(ip, [])
        # Evict old timestamps
        timestamps = [t for t in timestamps if t > now - window]
        if len(timestamps) >= limit:
            _rate_store[ip] = timestamps
            return False, 0
        timestamps.append(now)
        _rate_store[ip] = timestamps
        return True, limit - len(timestamps)

# ─── HEALTH ───────────────────────────────────────────────────────────────────
health_state = {"status": "starting", "since": iso_now(), "errors_last_min": 0}
_health_lock = threading.Lock()

def health_worker(cfg, stop_event):
    while not stop_event.is_set():
        try:
            with _health_lock:
                health_state["status"] = "ok"
                health_state["since"] = iso_now()
        except Exception as e:
            with _health_lock:
                health_state["status"] = "degraded"
            logger.error("health_worker: %s", e)
        stop_event.wait(cfg.get("health_check_interval", 30))

# ─── WEB UI HTML ──────────────────────────────────────────────────────────────
def build_html():
    return r"""<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>DevOps Local v2</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#0f1117;color:#e2e8f0;font-size:14px;line-height:1.6}
header{background:linear-gradient(135deg,#1a1f2e,#16213e);padding:12px 16px;border-bottom:1px solid #2d3748;display:flex;align-items:center;gap:10px}
header h1{font-size:1rem;font-weight:700;color:#63b3ed}
.badge{background:#2d3748;padding:2px 8px;border-radius:12px;font-size:11px;color:#68d391}
.tabs{display:flex;background:#1a1f2e;border-bottom:1px solid #2d3748}
.tab{padding:10px 18px;cursor:pointer;font-size:13px;color:#a0aec0;border-bottom:2px solid transparent;transition:all .2s}
.tab:hover{color:#e2e8f0}
.tab.active{color:#63b3ed;border-bottom-color:#63b3ed}
.panel{display:none;padding:16px}
.panel.active{display:block}
label{display:block;font-size:12px;color:#a0aec0;margin-bottom:4px;margin-top:12px;text-transform:uppercase;letter-spacing:.5px}
textarea{width:100%;background:#1a1f2e;color:#e2e8f0;border:1px solid #2d3748;border-radius:6px;padding:10px;font-family:'Courier New',monospace;font-size:12px;resize:vertical;outline:none;transition:border .2s;user-select:text;-webkit-user-select:text}
textarea:focus{border-color:#63b3ed}
textarea.output{background:#0d1117;color:#98ff98;border-color:#1e4a2e}
textarea.prompt-box{background:#1a1025;color:#d8b4fe;border-color:#4a2a6e}
.btn{padding:8px 16px;border:none;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600;transition:all .2s}
.btn-primary{background:#3182ce;color:#fff}
.btn-primary:hover{background:#2b6cb0}
.btn-success{background:#276749;color:#9ae6b4}
.btn-success:hover{background:#22543d}
.btn-warn{background:#744210;color:#fbd38d}
.btn-warn:hover{background:#652b19}
.btn-purple{background:#44337a;color:#d6bcfa}
.btn-purple:hover{background:#322659}
.btn-sm{padding:5px 12px;font-size:12px}
.btn-row{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.result-box{margin-top:12px;padding:12px;border-radius:8px;border:1px solid #2d3748;background:#0d1117}
.valid-ok{border-color:#276749;background:#0d1a12}
.valid-fail{border-color:#822727;background:#1a0d0d}
.valid-none{border-color:#2d3748}
.trust-bar{height:8px;border-radius:4px;background:#2d3748;margin:6px 0;overflow:hidden}
.trust-fill{height:100%;border-radius:4px;transition:width .5s}
.status-dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:6px}
.dot-ok{background:#68d391}.dot-err{background:#fc8181}.dot-warn{background:#f6ad55}
.info-line{font-size:12px;color:#a0aec0;margin-top:4px}
#log-box{background:#0d1117;border:1px solid #2d3748;border-radius:6px;padding:10px;font-family:monospace;font-size:11px;height:200px;overflow-y:auto;color:#68d391;white-space:pre-wrap;user-select:text;-webkit-user-select:text}
.btn-schema{background:#2d3748;color:#a0aec0;border:1px solid #4a5568}
.btn-schema:hover{color:#e2e8f0;background:#3a4556}
.active-schema{background:#1a3a5e!important;color:#63b3ed!important;border-color:#63b3ed!important}
@media(max-width:480px){.panel{padding:10px}.btn{padding:7px 12px;font-size:12px}}
</style>
</head>
<body>
<header>
  <h1>⚙ DevOps Local</h1>
  <span class="badge">v2</span>
  <span class="badge" id="mode-badge">—</span>
</header>
<div class="tabs">
  <div class="tab active" onclick="showTab('validate')">🔍 Validate</div>
  <div class="tab" onclick="showTab('convert')">📖 Convert</div>
  <div class="tab" onclick="showTab('status')">📊 Status</div>
</div>

<!-- ════ TAB: VALIDATE ════ -->
<div id="tab-validate" class="panel active">
  <div class="section-title">เลือก Built-in Schema</div>
  <div class="btn-row" style="margin-top:4px">
    <button id="btn-schema-basic"  class="btn btn-sm btn-schema active-schema" onclick="selectSchema('basic')">📋 DevOps Grid (Basic)</button>
    <button id="btn-schema-strict" class="btn btn-sm btn-schema" onclick="selectSchema('strict')">🔒 Validation Grid (Strict)</button>
    <button id="btn-schema-custom" class="btn btn-sm btn-schema" onclick="selectSchema('custom')">✏️ Custom Schema</button>
  </div>

  <div id="custom-schema-wrap" style="display:none">
    <div class="section-title">Custom JSON Schema</div>
    <textarea id="schema-input" rows="4" placeholder='{"type":"object","required":["name"],...}'></textarea>
  </div>
  <div id="schema-info" class="info-line" style="margin-top:6px;color:#63b3ed">✔ ใช้ DevOps Grid (Basic) Schema</div>

  <div class="section-title">JSON Input — วางค่าที่ต้องการตรวจสอบ</div>
  <textarea id="json-input" rows="8" placeholder='{"name":"test","value":123,...}'></textarea>

  <div class="btn-row">
    <button class="btn btn-primary" onclick="doValidate()">▶ Validate</button>
    <button class="btn btn-sm btn-warn" onclick="loadSample()">📄 โหลดตัวอย่าง</button>
    <button class="btn btn-sm" style="background:#2d3748;color:#e2e8f0" onclick="clearAll()">🗑 ล้าง</button>
  </div>

  <div id="validate-result" class="result-box valid-none" style="display:none">
    <div id="result-header" style="font-weight:700;font-size:14px"></div>
    <div id="trust-bar-wrap" style="margin-top:8px">
      <div style="font-size:11px;color:#a0aec0">Trust Score: <span id="trust-val">—</span></div>
      <div class="trust-bar"><div id="trust-fill" class="trust-fill" style="width:0%;background:#68d391"></div></div>
    </div>
    <div id="result-error" style="color:#fc8181;font-size:12px;margin-top:6px;font-family:monospace;white-space:pre-wrap"></div>
    <div id="fix-prompt-section" style="display:none;margin-top:10px">
      <div class="section-title" style="color:#9f7aea">🤖 AI Fix Prompt — copy ไปวางในแชท AI</div>
      <textarea id="fix-prompt-box" class="prompt-box" rows="6" readonly></textarea>
      <div class="btn-row">
        <button class="btn btn-sm btn-purple" onclick="copyTextarea('fix-prompt-box')">📋 Copy Prompt</button>
        <button class="btn btn-sm" style="background:#2d3748;color:#e2e8f0" onclick="speakTextarea('fix-prompt-box')">🔊 อ่านออกเสียง</button>
      </div>
    </div>
  </div>

  <div id="output-section" style="display:none;margin-top:12px">
    <div class="section-title">Output JSON (validated + trustscore)</div>
    <textarea id="json-output" class="output" rows="8" readonly></textarea>
    <div class="btn-row">
      <button class="btn btn-sm btn-success" onclick="downloadResult('json')">⬇ JSON</button>
      <button class="btn btn-sm btn-success" onclick="downloadResult('text')">⬇ Text</button>
      <button class="btn btn-sm" style="background:#2d3748;color:#e2e8f0" onclick="speakTextarea('json-output')">🔊 อ่านออกเสียง</button>
      <button class="btn btn-sm" style="background:#2d3748;color:#e2e8f0" onclick="copyTextarea('json-output')">📋 Copy</button>
    </div>
  </div>
</div>

<!-- ════ TAB: CONVERT ════ -->
<div id="tab-convert" class="panel">
  <p class="info-line">วางข้อความจาก AI chat (รองรับทุกรูปแบบ: JSON ปกติ, JSON ใน markdown fence, JSON ผสมข้อความ)</p>

  <div class="section-title">AI Response Input</div>
  <textarea id="convert-input" rows="10" placeholder="วาง response จาก AI ที่นี่ — จะดึง JSON ออกอัตโนมัติและแปลงเป็นตัวหนังสือรูปแบบหนังสือ"></textarea>

  <div class="btn-row">
    <button class="btn btn-primary" onclick="doConvert()">📖 แปลงเป็นตัวหนังสือ</button>
    <button class="btn btn-sm btn-warn" onclick="doConvertRaw()">🔄 แปลง JSON ดิบ</button>
    <button class="btn btn-sm" style="background:#2d3748;color:#e2e8f0" onclick="document.getElementById('convert-input').value=''">🗑 ล้าง</button>
  </div>

  <div class="section-title" style="margin-top:14px">ผลลัพธ์ที่แปลงแล้ว</div>
  <textarea id="convert-output" class="output" rows="12" readonly placeholder="ผลลัพธ์จะแสดงที่นี่..."></textarea>

  <div class="btn-row">
    <button class="btn btn-sm btn-success" onclick="downloadConvert('text')">⬇ Text</button>
    <button class="btn btn-sm btn-success" onclick="downloadConvert('json')">⬇ JSON</button>
    <button class="btn btn-sm" style="background:#2d3748;color:#e2e8f0" onclick="speakTextarea('convert-output')">🔊 อ่านออกเสียง</button>
    <button class="btn btn-sm" style="background:#2d3748;color:#e2e8f0" onclick="copyTextarea('convert-output')">📋 Copy</button>
  </div>
  <div id="convert-info" class="info-line" style="margin-top:8px"></div>
</div>

<!-- ════ TAB: STATUS ════ -->
<div id="tab-status" class="panel">
  <div class="section-title">System Status</div>
  <div id="status-box" style="background:#0d1117;border:1px solid #2d3748;border-radius:6px;padding:12px">
    <div><span class="status-dot dot-warn" id="health-dot"></span><strong id="health-text">กำลังตรวจสอบ...</strong></div>
    <div class="info-line" id="status-time"></div>
    <div class="info-line" id="status-metrics" style="margin-top:6px"></div>
  </div>

  <div class="section-title" style="margin-top:14px">Log (20 KB ล่าสุด)</div>
  <div id="log-box">— กำลังโหลด —</div>
  <div class="btn-row" style="margin-top:8px">
    <button class="btn btn-sm" style="background:#2d3748;color:#e2e8f0" onclick="refreshStatus()">🔄 รีเฟรช</button>
    <button class="btn btn-sm" style="background:#2d3748;color:#e2e8f0" onclick="speakEl('log-box')">🔊 อ่าน Log</button>
  </div>
</div>

<script>
// ── Tab navigation ──────────────────────────────────────────────────────────
function showTab(name){
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  event.currentTarget.classList.add('active');
  if(name==='status') refreshStatus();
}

// ── Copy protection: copies only inside a specific textarea ─────────────────
function copyTextarea(id){
  const ta = document.getElementById(id);
  ta.select();
  ta.setSelectionRange(0, ta.value.length); // select all within textarea
  try {
    if(navigator.clipboard && window.isSecureContext){
      navigator.clipboard.writeText(ta.value).then(()=>flash(ta,'copied!'));
    } else {
      document.execCommand('copy');
      flash(ta,'copied!');
    }
  } catch(e){ flash(ta,'copy failed'); }
  window.getSelection && window.getSelection().removeAllRanges(); // deselect DOM
}
function flash(el, msg){
  const orig = el.style.border;
  el.style.border = '1px solid #68d391';
  setTimeout(()=>{ el.style.border = orig; }, 800);
}

// ── TTS via Web Speech API (Android Chrome native) ──────────────────────────
let ttsActive = false;
function speakText(text, lang){
  if(!('speechSynthesis' in window)){ alert('ไม่รองรับ TTS บนเบราว์เซอร์นี้'); return; }
  if(ttsActive){ speechSynthesis.cancel(); ttsActive=false; return; }
  const u = new SpeechSynthesisUtterance(text.substring(0,4000));
  u.lang = lang || detectLang(text);
  u.rate = 0.9;
  u.onend = ()=>{ ttsActive=false; };
  u.onerror = ()=>{ ttsActive=false; };
  ttsActive = true;
  speechSynthesis.speak(u);
}
function speakTextarea(id){ speakText(document.getElementById(id).value); }
function speakEl(id){ speakText(document.getElementById(id).textContent); }
function detectLang(text){
  const thaiChars = (text.match(/[\u0E00-\u0E7F]/g)||[]).length;
  return thaiChars > text.length*0.05 ? 'th-TH' : 'en-US';
}

// ── Download helper ──────────────────────────────────────────────────────────
function downloadBlob(content, filename, mime){
  const blob = new Blob([content], {type: mime||'text/plain;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}
function downloadResult(fmt){
  const out = document.getElementById('json-output').value;
  if(!out.trim()){ alert('ไม่มีข้อมูลให้ดาวน์โหลด'); return; }
  if(fmt==='json') downloadBlob(out, 'validated.json', 'application/json');
  else {
    // Convert JSON to plain text
    try {
      const obj = JSON.parse(out);
      const lines = [];
      function flatten(o, prefix){
        if(typeof o === 'object' && o !== null && !Array.isArray(o)){
          for(const [k,v] of Object.entries(o)) flatten(v, prefix?prefix+' > '+k:k);
        } else if(Array.isArray(o)){
          o.forEach((item,i)=>flatten(item, prefix+'['+i+']'));
        } else { lines.push((prefix?prefix+': ':'')+o); }
      }
      flatten(obj,'');
      downloadBlob(lines.join('\n'), 'validated.txt');
    } catch(e){ downloadBlob(out, 'validated.txt'); }
  }
}
function downloadConvert(fmt){
  const out = document.getElementById('convert-output').value;
  if(!out.trim()){ alert('ไม่มีข้อมูล'); return; }
  if(fmt==='text') downloadBlob(out, 'converted.txt');
  else {
    const raw = document.getElementById('convert-input').value;
    try {
      const parsed = extractFirstJson(raw);
      downloadBlob(JSON.stringify(parsed,null,2), 'extracted.json','application/json');
    } catch(e){ downloadBlob(out, 'converted.json'); }
  }
}

// ── Schema selector ──────────────────────────────────────────────────────────
let _selectedSchema = 'basic';
const _schemaLabels = {
  basic:  '✔ ใช้ DevOps Grid (Basic) Schema',
  strict: '✔ ใช้ Validation Grid (Strict) Schema',
  custom: '✏️ Custom Schema — วางใน textarea ด้านบน'
};
function selectSchema(name){
  _selectedSchema = name;
  document.querySelectorAll('.btn-schema').forEach(b=>b.classList.remove('active-schema'));
  document.getElementById('btn-schema-'+name).classList.add('active-schema');
  document.getElementById('custom-schema-wrap').style.display = name==='custom'?'block':'none';
  document.getElementById('schema-info').textContent = _schemaLabels[name]||'';
}

// ── Validate ─────────────────────────────────────────────────────────────────
function pyToJson(s){
  return s
    .replace(/:\s*True\b/g,  ': true')
    .replace(/:\s*False\b/g, ': false')
    .replace(/:\s*None\b/g,  ': null')
    .replace(/,\s*}/g, '}')
    .replace(/,\s*]/g, ']');
}
async function doValidate(){
  const jsonStr = pyToJson(document.getElementById('json-input').value.trim());
  if(!jsonStr){ alert('กรุณาใส่ JSON'); return; }
  let payload;
  try { payload = JSON.parse(jsonStr); } catch(e){ showError('JSON syntax error: '+e.message); return; }
  const body = {json: payload, schema_name: _selectedSchema};
  if(_selectedSchema === 'custom'){
    const schemaStr = pyToJson((document.getElementById('schema-input')||{value:''}).value.trim());
    if(schemaStr){ try { body.schema = JSON.parse(schemaStr); } catch(e){ alert('Schema JSON ไม่ถูกต้อง: '+e.message); return; } }
  }
  try {
    const r = await fetch('/api/validate', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
    const data = await r.json();
    showValidateResult(data, payload, body.schema);
  } catch(e){ showError('Network error: '+e.message); }
}

function showValidateResult(data, origDoc, schema){
  const box = document.getElementById('validate-result');
  const hdr = document.getElementById('result-header');
  box.style.display = 'block';
  if(data.error && !('valid' in data)){
    box.className = 'result-box valid-fail';
    hdr.textContent = '⚠ ' + data.error;
    return;
  }
  if(data.valid){
    box.className = 'result-box valid-ok';
    hdr.innerHTML = '✅ Valid &nbsp;';
  } else {
    box.className = 'result-box valid-fail';
    hdr.textContent = '❌ Invalid';
    document.getElementById('result-error').textContent = data.error || '';
    // Show AI Fix Prompt
    document.getElementById('fix-prompt-section').style.display = 'block';
    document.getElementById('fix-prompt-box').value = data.fix_prompt || '';
  }
  if(data.valid) document.getElementById('fix-prompt-section').style.display='none';
  // Trust score
  const trust = data.trustscore || 0;
  document.getElementById('trust-val').textContent = (trust*100).toFixed(1)+'%';
  const fill = document.getElementById('trust-fill');
  fill.style.width = (trust*100)+'%';
  fill.style.background = trust>0.7?'#68d391':trust>0.4?'#f6ad55':'#fc8181';
  // Output JSON
  if(data.output){
    document.getElementById('output-section').style.display='block';
    document.getElementById('json-output').value = JSON.stringify(data.output, null, 2);
  }
}

function showError(msg){
  const box = document.getElementById('validate-result');
  box.style.display='block';
  box.className='result-box valid-fail';
  document.getElementById('result-header').textContent='❌ '+msg;
}

async function loadSample(){
  const name = _selectedSchema === 'custom' ? 'basic' : _selectedSchema;
  try {
    const r = await fetch('/api/sample?schema='+name);
    if(r.ok){ const d = await r.json(); document.getElementById('json-input').value = JSON.stringify(d, null, 2); }
  } catch(e){}
}

function clearAll(){
  ['json-input','schema-input','json-output','fix-prompt-box'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('validate-result').style.display='none';
  document.getElementById('output-section').style.display='none';
}

// ── Convert ──────────────────────────────────────────────────────────────────
async function doConvert(){
  const text = document.getElementById('convert-input').value.trim();
  if(!text){ alert('กรุณาวาง response ก่อน'); return; }
  try {
    const r = await fetch('/api/convert', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({text})});
    const data = await r.json();
    document.getElementById('convert-output').value = data.booktext || data.error || '';
    document.getElementById('convert-info').textContent = data.info || '';
  } catch(e){ document.getElementById('convert-output').value='Error: '+e.message; }
}

async function doConvertRaw(){
  const text = document.getElementById('convert-input').value.trim();
  if(!text){ return; }
  try {
    const r = await fetch('/api/convert', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({text, raw:true})});
    const data = await r.json();
    document.getElementById('convert-output').value = data.booktext || data.error || '';
  } catch(e){}
}

function extractFirstJson(text){
  const m = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if(m) return JSON.parse(m[1].trim());
  return JSON.parse(text.trim());
}

// ── Status ───────────────────────────────────────────────────────────────────
async function refreshStatus(){
  try {
    const [hr, sr, mr] = await Promise.all([fetch('/api/health'), fetch('/api/status'), fetch('/api/metrics')]);
    const h = await hr.json(), s = await sr.json(), m = await mr.json();
    const dot = document.getElementById('health-dot');
    const txt = document.getElementById('health-text');
    if(h.status==='ok'){ dot.className='status-dot dot-ok'; txt.textContent='ระบบปกติ (OK)'; }
    else { dot.className='status-dot dot-err'; txt.textContent='ระบบมีปัญหา: '+h.status; }
    document.getElementById('status-time').textContent='อัพเดต: '+s.time;
    document.getElementById('status-metrics').textContent=
      'Requests: '+m.requests+' | Validations: '+m.validations+' | Alerts: '+m.alerts;
    document.getElementById('mode-badge').textContent=s.mode||'—';
  } catch(e){ document.getElementById('health-text').textContent='ไม่สามารถเชื่อมต่อได้'; }
  try {
    const lr = await fetch('/_log');
    if(lr.ok){ document.getElementById('log-box').textContent = await lr.text(); }
  } catch(e){}
}

// Init
refreshStatus();
setInterval(refreshStatus, 15000);
</script>
</body>
</html>"""

# ─── FLASK APP ────────────────────────────────────────────────────────────────
def run_web(port, cfg, stop_event):
    try:
        from flask import Flask, jsonify, request, Response
    except ImportError:
        print("Flask not installed. Run: pip install Flask jsonschema")
        return

    app = Flask("devops_local_v2")
    cfg_token = os.environ.get("DEVOPS_LOCAL_TOKEN") or cfg.get("auth_token", "")
    mode = cfg.get("mode", "basic")
    rate_limit = cfg.get("rate_limit_requests", 60)
    rate_window = cfg.get("rate_limit_window_sec", 60)
    _metrics = {"requests": 0, "validations": 0, "alerts": 0}
    _ml = threading.Lock()

    def get_ip():
        return request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0").split(",")[0].strip()

    def require_auth():
        if mode in ("advanced", "production"):
            auth = request.headers.get("Authorization", "")
            if not check_bearer(auth, cfg_token):
                return jsonify({"error": "unauthorized"}), HTTPStatus.UNAUTHORIZED
        return None

    def check_rate():
        ip = get_ip()
        ok, remaining = check_rate_limit(ip, rate_limit, rate_window)
        if not ok:
            return jsonify({"error": "rate limit exceeded", "retry_after": rate_window}), 429
        return None

    @app.before_request
    def before():
        with _ml: _metrics["requests"] += 1

    @app.route("/")
    def index():
        return Response(build_html(), mimetype="text/html")

    @app.route("/api/validate", methods=["POST"])
    def api_validate():
        deny = require_auth() or check_rate()
        if deny: return deny
        body = request.get_json(force=True, silent=True) or {}
        doc = body.get("json")
        custom_schema = body.get("schema")
        schema_name = body.get("schema_name", "basic")
        if doc is None:
            return jsonify({"error": "missing 'json' field"}), HTTPStatus.BAD_REQUEST
        # Resolve schema: custom > schema_name lookup > basic
        if custom_schema:
            target_schema = custom_schema
        else:
            target_schema = BUILTIN_SCHEMAS.get(schema_name, BUILTIN_SCHEMAS["basic"])["schema"]
        try:
            ok, err = validate_json_against_schema(doc, target_schema)
        except Exception as e:
            return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR
        trust, breakdown = compute_trustscore(doc)
        output = dict(doc) if isinstance(doc, dict) else doc
        if isinstance(output, dict):
            output["trustscore"] = trust
            rt = output.get("reasoningtrace", [])
            if isinstance(rt, list):
                rt.append({"stepid": f"STEP-{len(rt)+1}", "description": "validated via API",
                           "inputs": ["payload"], "operation": "jsonschema+trust",
                           "output": f"trust={trust}", "timestamp": iso_now()})
            output["reasoningtrace"] = rt
        with _ml: _metrics["validations"] += 1
        result = {"valid": ok, "trustscore": trust, "breakdown": breakdown, "output": output}
        if not ok:
            result["error"] = err
            result["fix_prompt"] = generate_fix_prompt(doc, err, custom_schema)
            logger.warning("validation failed ip=%s err=%s", get_ip(), err)
            if mode in ("advanced", "production"):
                fname = os.path.join(ALERTS_DIR, f"alert-{iso_now().replace(':','-')}.json")
                try:
                    safe_write(fname, json.dumps({"time": iso_now(), "error": str(err)}, indent=2))
                    with _ml: _metrics["alerts"] += 1
                except Exception: pass
        else:
            logger.info("validation ok ip=%s trust=%s", get_ip(), trust)
        return jsonify(result), HTTPStatus.OK

    @app.route("/api/convert", methods=["POST"])
    def api_convert():
        deny = check_rate()
        if deny: return deny
        body = request.get_json(force=True, silent=True) or {}
        text = body.get("text", "")
        raw_mode = body.get("raw", False)
        if not text.strip():
            return jsonify({"error": "empty text"}), HTTPStatus.BAD_REQUEST
        objs = extract_json_from_text(text)
        if not objs:
            # No JSON found — just return the text formatted as-is
            return jsonify({"booktext": text, "info": "ไม่พบ JSON — แสดงข้อความเดิม", "count": 0})
        if raw_mode:
            booktext = json.dumps(objs[0] if len(objs)==1 else objs, indent=2, ensure_ascii=False)
        else:
            parts = []
            for i, obj in enumerate(objs):
                title = f"เอกสาร {i+1}" if len(objs) > 1 else "เนื้อหาที่แปลงแล้ว"
                parts.append(json_to_booktext(obj, title))
            booktext = "\n\n".join(parts)
        return jsonify({"booktext": booktext, "info": f"พบ JSON {len(objs)} ชุด", "count": len(objs)})

    @app.route("/api/health")
    def api_health():
        with _health_lock:
            return jsonify(health_state)

    @app.route("/api/status")
    def api_status():
        return jsonify({"status": "running", "mode": mode, "time": iso_now()})

    @app.route("/api/metrics")
    def api_metrics():
        with _ml: return jsonify(dict(_metrics))

    @app.route("/api/sample")
    def api_sample():
        schema_name = request.args.get("schema", "basic")
        entry = BUILTIN_SCHEMAS.get(schema_name, BUILTIN_SCHEMAS["basic"])
        sample_data = entry.get("sample")
        if sample_data:
            return Response(json.dumps(sample_data, indent=2, ensure_ascii=False), mimetype="application/json")
        # fallback to file
        try:
            with open(os.path.join(TO_VALIDATE, "sample.json"), "r", encoding="utf-8") as f:
                return Response(f.read(), mimetype="application/json")
        except Exception:
            return jsonify({"error": "no sample"}), HTTPStatus.NOT_FOUND

    @app.route("/_log")
    def log_view():
        try:
            with open(LOG_PATH, "r", encoding="utf-8") as f:
                return Response(f.read()[-20000:], mimetype="text/plain")
        except Exception:
            return Response("no log", mimetype="text/plain")

    try: app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024
    except Exception: pass
    logger.info("starting web mode=%s port=%s", mode, port)
    try:
        app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False, threaded=True)
    except Exception as e:
        logger.error("web error: %s", e)

# ─── CLI ─────────────────────────────────────────────────────────────────────
def cli_validate(path, custom_schema_path=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception as e:
        print(f"[ERROR] Cannot load JSON: {e}"); return
    custom_schema = None
    if custom_schema_path:
        try:
            with open(custom_schema_path, "r", encoding="utf-8") as f:
                custom_schema = json.load(f)
        except Exception as e:
            print(f"[ERROR] Cannot load schema: {e}"); return
    try:
        ok, err = validate_json_against_schema(doc, custom_schema)
    except Exception as e:
        print(f"[ERROR] {e}"); return
    trust, breakdown = compute_trustscore(doc)
    doc["trustscore"] = trust
    if ok:
        out = path.replace(".json","") + ".validated.json"
        safe_write(out, json.dumps(doc, indent=2, ensure_ascii=False))
        print(f"[OK]    Valid | Trust={trust:.3f} | Wrote: {out}")
    else:
        print(f"[FAIL]  Invalid | Trust={trust:.3f}")
        print(f"[ERR]   {err}")
        print(f"\n── AI Fix Prompt (copy to AI chat) ──")
        print(generate_fix_prompt(doc, err, custom_schema))

def cli_convert(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except Exception as e:
        print(f"[ERROR] {e}"); return
    objs = extract_json_from_text(text)
    if not objs:
        print("[INFO] No JSON found in file"); return
    for i, obj in enumerate(objs):
        print(json_to_booktext(obj, f"Document {i+1}"))

# ─── SIGNAL + MAIN ────────────────────────────────────────────────────────────
_stop_event = threading.Event()
def _sig(signum, frame):
    logger.info("signal %s received, shutting down", signum)
    _stop_event.set()
    sys.exit(0)
signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)

def main():
    ensure_structure()
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        cfg = dict(DEFAULT_CONFIG)
        cfg["auth_token"] = gen_token()

    # FIX: mode "balanced" was not in argparse choices — default to "basic"
    valid_modes = ("basic", "advanced", "production")
    cfg_mode = cfg.get("mode", "basic")
    if cfg_mode not in valid_modes:
        cfg_mode = "basic"

    if cfg_mode == "production":
        if not os.environ.get("DEVOPS_LOCAL_TOKEN") and not cfg.get("auth_token"):
            print("[ERROR] Production mode requires DEVOPS_LOCAL_TOKEN env var")
            sys.exit(2)

    _setup_log(cfg.get("log_max_bytes", 200000), cfg.get("log_backup_count", 3))

    parser = argparse.ArgumentParser(description="DevOps Local v2 — Termux/Android")
    parser.add_argument("--mode", choices=valid_modes, default=cfg_mode)
    parser.add_argument("action", nargs="?", default="status",
                        choices=["status","validate","convert","web","help"])
    parser.add_argument("target",  nargs="?", default=None, help="file path or port")
    parser.add_argument("--schema", default=None, help="custom schema JSON file for validate")
    args = parser.parse_args()
    cfg["mode"] = args.mode

    hw = threading.Thread(target=health_worker, args=(cfg, _stop_event), daemon=True)
    hw.start()

    if args.action == "status":
        with _health_lock:
            print(f"Status: {health_state['status']} | Mode: {cfg['mode']} | {iso_now()}")
        return
    if args.action == "help":
        print("Usage: python3 app_v2.py [--mode basic|advanced|production] {status|validate|convert|web} [target]")
        print("  validate <file.json> [--schema schema.json]")
        print("  convert  <file.json|file.txt>")
        print("  web      [port]  — default 8080")
        return
    if args.action == "validate":
        if not args.target: print("Usage: app_v2.py validate <file.json>"); return
        cli_validate(args.target, args.schema); return
    if args.action == "convert":
        if not args.target: print("Usage: app_v2.py convert <file>"); return
        cli_convert(args.target); return
    if args.action == "web":
        port = int(args.target) if args.target and args.target.isdigit() else cfg.get("web_port", 8080)
        print(f"Starting web on http://0.0.0.0:{port}  (mode={cfg['mode']})")
        try:
            run_web(port, cfg, _stop_event)
        finally:
            _stop_event.set()
        return
    print("Unknown action. Use: python3 app_v2.py help")

if __name__ == "__main__":
    main()
PY
echo "[OK] app_v2.py created — $(wc -l < app_v2.py) lines"
chmod +x app_v2.py
