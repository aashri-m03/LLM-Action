from flask import Flask, request, jsonify
import os
import re
from urllib.parse import urlparse

app = Flask(__name__)

TENANT = "tenant-wpa3ks7"
EMAIL_DOMAIN = "notify-dlpb2ta.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html"
}


def block(reason):
    return jsonify({
        "decision": "block",
        "reason": reason
    })


@app.route("/")
def home():
    return "Action Firewall is running"


@app.route("/action-firewall", methods=["POST"])
def action_firewall():

    # -----------------------------
    # 1. Top-level schema
    # -----------------------------

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return block("INVALID_SCHEMA")

    if set(data.keys()) != {
        "provenance",
        "humanApproved",
        "untrustedContent",
        "action"
    }:
        return block("INVALID_SCHEMA")

    if data["provenance"] not in {"trusted", "untrusted"}:
        return block("INVALID_SCHEMA")

    if not isinstance(data["humanApproved"], bool):
        return block("INVALID_SCHEMA")

    if not isinstance(data["untrustedContent"], str):
        return block("INVALID_SCHEMA")

    action = data["action"]

    if not isinstance(action, dict):
        return block("INVALID_SCHEMA")

    if set(action.keys()) != {"tool", "args"}:
        return block("INVALID_SCHEMA")

    if not isinstance(action["tool"], str):
        return block("INVALID_SCHEMA")

    if not isinstance(action["args"], dict):
        return block("INVALID_SCHEMA")

    tool = action["tool"]
    args = action["args"]

    # -----------------------------
    # 2. Tool allowlist
    # -----------------------------

    if tool not in ALLOWED_TOOLS:
        return block("TOOL_NOT_ALLOWED")

    # -----------------------------
    # 3. Tool argument schemas
    # -----------------------------

    if tool == "search":

        if set(args.keys()) != {"query"}:
            return block("INVALID_SCHEMA")

        query = args["query"]

        if not isinstance(query, str):
            return block("INVALID_SCHEMA")

        if not (1 <= len(query) <= 200):
            return block("INVALID_SCHEMA")

    elif tool == "lookup_record":

        if set(args.keys()) != {"tenantId", "recordId"}:
            return block("INVALID_SCHEMA")

        if not isinstance(args["tenantId"], str):
            return block("INVALID_SCHEMA")

        if not isinstance(args["recordId"], str):
            return block("INVALID_SCHEMA")

        if args["recordId"] == "":
            return block("INVALID_SCHEMA")

    elif tool == "send_email":

        if set(args.keys()) != {"to", "subject", "body"}:
            return block("INVALID_SCHEMA")

        if not all(isinstance(args[x], str)
                   for x in ["to", "subject", "body"]):
            return block("INVALID_SCHEMA")

    elif tool == "render_html":

        if set(args.keys()) != {"html"}:
            return block("INVALID_SCHEMA")

        if not isinstance(args["html"], str):
            return block("INVALID_SCHEMA")

    # -----------------------------
    # 4. Tenant scope
    # -----------------------------

    if tool == "lookup_record":

        if args["tenantId"] != TENANT:
            return block("TENANT_SCOPE")

    # -----------------------------
    # 5. Egress / email domain
    # -----------------------------

    if tool == "send_email":

        recipient = args["to"]

        # Must be a simple email address with exactly
        # the assigned domain.
        if "@" not in recipient:
            return block("EGRESS_DENIED")

        local, domain = recipient.rsplit("@", 1)

        if not local or domain != EMAIL_DOMAIN:
            return block("EGRESS_DENIED")

    # -----------------------------
    # 6. Human approval
    # -----------------------------

    if tool == "send_email":

        if data["humanApproved"] is not True:
            return block("APPROVAL_REQUIRED")

    # -----------------------------
    # 7. HTML safety
    # -----------------------------

    if tool == "render_html":

        html = args["html"]

        # scripts
        if re.search(r"<\s*script\b", html, re.IGNORECASE):
            return block("UNSAFE_OUTPUT")

        # iframes
        if re.search(r"<\s*iframe\b", html, re.IGNORECASE):
            return block("UNSAFE_OUTPUT")

        # inline event handlers: onclick=, onload=, etc.
        if re.search(r"\bon[a-z]+\s*=", html, re.IGNORECASE):
            return block("UNSAFE_OUTPUT")

        # javascript: URLs
        if re.search(r"javascript\s*:", html, re.IGNORECASE):
            return block("UNSAFE_OUTPUT")

    # -----------------------------
    # Everything passed
    # -----------------------------

    return jsonify({
        "decision": "allow",
        "reason": "ALLOW"
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )
