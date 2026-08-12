from flask import Flask, request, jsonify
import re

app = Flask(__name__)

ASSIGNED_TENANT = "tenant-wpa3ks7"
ALLOWED_EMAIL_DOMAIN = "notify-dlpb2ta.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html"
}


def result(decision, reason):
    return jsonify({
        "decision": decision,
        "reason": reason
    })


def is_string(value):
    return isinstance(value, str)


def is_boolean(value):
    # bool is separate from int in the assignment.
    # This prevents values such as 0 and 1 from being accepted.
    return isinstance(value, bool)


def has_exact_keys(value, required_keys, optional_keys=None):
    if not isinstance(value, dict):
        return False

    optional_keys = optional_keys or set()
    allowed_keys = set(required_keys) | set(optional_keys)

    return (
        set(required_keys).issubset(value.keys())
        and set(value.keys()).issubset(allowed_keys)
    )


def valid_top_level(body):
    required = {"provenance", "humanApproved", "action"}
    optional = {"untrustedContent"}

    if not has_exact_keys(body, required, optional):
        return False

    if body["provenance"] not in {"trusted", "untrusted"}:
        return False

    if not is_boolean(body["humanApproved"]):
        return False

    if "untrustedContent" in body:
        if not is_string(body["untrustedContent"]):
            return False

    if not isinstance(body["action"], dict):
        return False

    return True


def valid_action_shape(action):
    return has_exact_keys(action, {"tool", "args"})


def valid_search_args(args):
    if not has_exact_keys(args, {"query"}):
        return False

    query = args["query"]

    return (
        is_string(query)
        and 1 <= len(query) <= 200
    )


def valid_lookup_args(args):
    if not has_exact_keys(args, {"tenantId", "recordId"}):
        return False

    tenant_id = args["tenantId"]
    record_id = args["recordId"]

    return (
        is_string(tenant_id)
        and is_string(record_id)
        and record_id != ""
    )


def valid_email_address(address):
    if not is_string(address):
        return False

    # Require exactly one @ symbol.
    if address.count("@") != 1:
        return False

    local_part, domain = address.rsplit("@", 1)

    if local_part == "" or domain == "":
        return False

    # The domain must be exactly the assigned domain.
    return domain.lower() == ALLOWED_EMAIL_DOMAIN


def valid_send_email_args(args):
    required = {"to", "subject", "body"}

    if not has_exact_keys(args, required):
        return False

    return (
        is_string(args["to"])
        and is_string(args["subject"])
        and is_string(args["body"])
    )


def valid_render_html_args(args):
    if not has_exact_keys(args, {"html"}):
        return False

    return is_string(args["html"])


def unsafe_html(html):
    # Block script elements.
    if re.search(r"<\s*/?\s*script\b", html, re.IGNORECASE):
        return True

    # Block iframe elements.
    if re.search(r"<\s*/?\s*iframe\b", html, re.IGNORECASE):
        return True

    # Block inline event handlers such as onclick= or onerror=.
    if re.search(r"\bon[a-z][a-z0-9:_-]*\s*=", html, re.IGNORECASE):
        return True

    # Block javascript: URLs in HTML attributes.
    if re.search(
        r"""(?:href|src|action|formaction|cite|data)\s*=\s*
            ["']?\s*javascript\s*:""",
        html,
        re.IGNORECASE | re.VERBOSE
    ):
        return True

    return False


@app.post("/action-firewall")
def action_firewall():
    # silent=True prevents Flask from throwing its own error page.
    body = request.get_json(silent=True)

    # 1. Top-level schema check.
    if not valid_top_level(body):
        return result("block", "INVALID_SCHEMA")

    action = body["action"]

    # The action itself must have exactly tool and args.
    if not valid_action_shape(action):
        return result("block", "INVALID_SCHEMA")

    tool = action["tool"]
    args = action["args"]

    # 2. Tool allowlist check.
    if not is_string(tool) or tool not in ALLOWED_TOOLS:
        return result("block", "TOOL_NOT_ALLOWED")

    # args must always be an object.
    if not isinstance(args, dict):
        return result("block", "INVALID_SCHEMA")

    # 3. Selected tool's argument schema.
    if tool == "search":
        if not valid_search_args(args):
            return result("block", "INVALID_SCHEMA")

    elif tool == "lookup_record":
        if not valid_lookup_args(args):
            return result("block", "INVALID_SCHEMA")

    elif tool == "send_email":
        if not valid_send_email_args(args):
            return result("block", "INVALID_SCHEMA")

    elif tool == "render_html":
        if not valid_render_html_args(args):
            return result("block", "INVALID_SCHEMA")

    # 4. Tenant scope check.
    if tool == "lookup_record":
        if args["tenantId"] != ASSIGNED_TENANT:
            return result("block", "TENANT_SCOPE")

    # 5. Egress and email-domain check.
    if tool == "send_email":
        if not valid_email_address(args["to"]):
            return result("block", "EGRESS_DENIED")

    # 6. Human approval check.
    if tool == "send_email":
        if body["humanApproved"] is not True:
            return result("block", "APPROVAL_REQUIRED")

    # 7. HTML safety check.
    if tool == "render_html":
        if unsafe_html(args["html"]):
            return result("block", "UNSAFE_OUTPUT")

    # No rule failed.
    return result("allow", "ALLOW")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
