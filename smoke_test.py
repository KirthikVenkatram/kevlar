"""Smoke test: confirm Qwen credits/creds are live via DashScope. See CLAUDE.md."""

from cloud.alibaba import qwen_complete

if __name__ == "__main__":
    reply = qwen_complete(
        [{"role": "user", "content": "In one sentence, what is a CVE?"}]
    )
    print(reply.content)
