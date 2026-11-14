import streamlit as st
import requests
import hashlib
import subprocess
import re

# Page Config & Dark Mode Styling matching your target UI
st.set_page_config(page_title="AML OSINT Intelligence Engine", page_icon="🔍", layout="wide")

st.markdown("""
<style>
    .stApp { background-color: #121212; color: #e0e0e0; }
    .summary-card {
        background-color: #1e1e1e; border: 1px solid #2c2c2c;
        border-radius: 8px; padding: 15px; margin-bottom: 15px;
    }
    .result-card {
        background-color: #1e1e1e; border: 1px solid #2c2c2c;
        border-radius: 8px; padding: 18px; margin-bottom: 12px;
    }
    .platform-badge {
        font-size: 11px; font-weight: 700; color: #3b82f6;
        text-transform: uppercase; letter-spacing: 0.6px;
    }
    .target-title { font-size: 16px; font-weight: 600; color: #ffffff; margin: 4px 0; }
    .detail-text { font-size: 13px; color: #b0b0b0; }
    .tag {
        display: inline-block; background: #2c2c2c; color: #e0e0e0;
        padding: 3px 9px; border-radius: 4px; font-size: 12px; margin: 2px;
    }
</style>
""", unsafe_allow_html=True)

# Built-in India, US & Canada Telecom Database
AREA_CODES = {
    "416": "Toronto, Ontario, Canada 🇨🇦", "647": "Toronto, Ontario, Canada 🇨🇦",
    "613": "Ottawa, Ontario, Canada 🇨🇦", "514": "Montreal, Quebec, Canada 🇨🇦",
    "604": "Vancouver, BC, Canada 🇨🇦", "403": "Calgary, Alberta, Canada 🇨🇦",
    "212": "New York City, NY, USA 🇺🇸", "415": "San Francisco, CA, USA 🇺🇸",
    "310": "Los Angeles, CA, USA 🇺🇸", "312": "Chicago, IL, USA 🇺🇸",
    "305": "Miami, FL, USA 🇺🇸", "202": "Washington, D.C., USA 🇺🇸",
    "206": "Seattle, WA, USA 🇺🇸", "302": "Delaware (Corporate Hub), USA 🇺🇸"
}

INDIA_SERIES = {
    "9840": "Airtel - Chennai / TN, India 🇮🇳", "9444": "BSNL - Chennai, India 🇮🇳",
    "9845": "Airtel - Karnataka, India 🇮🇳", "9820": "Vi - Mumbai, India 🇮🇳",
    "9810": "Airtel - Delhi NCR, India 🇮🇳", "7012": "Jio - Kerala, India 🇮🇳",
    "7034": "Jio - Kerala, India 🇮🇳", "9447": "BSNL - Kerala, India 🇮🇳"
}

def analyze_phone(raw_phone):
    digits = re.sub(r"[^0-9]", "", raw_phone)
    if not digits:
        return None
    if digits.startswith("91") and len(digits) == 12:
        local = digits[2:]
        return INDIA_SERIES.get(local[:4], "India Mobile Network (+91) 🇮🇳")
    if len(digits) == 10 and digits[0] in "6789" and not raw_phone.strip().startswith("+1"):
        return INDIA_SERIES.get(digits[:4], "India Mobile Network (+91) 🇮🇳")
    if (digits.startswith("1") and len(digits) == 11) or (len(digits) == 10 and raw_phone.strip().startswith("+1")):
        local = digits[1:] if len(digits) == 11 else digits
        return AREA_CODES.get(local[:3], "North America (US / Canada +1) 🇺🇸🇨🇦")
    return f"International Telecom (+{digits[:2]}) 🌍"

def check_gravatar(email):
    h = hashlib.sha256(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/avatar/{h}?d=404&s=200"
    try:
        r = requests.get(url, timeout=4)
        if r.status_code == 200:
            return url
    except Exception:
        pass
    return None

def check_github_username(username):
    clean = username.strip().replace(" ", "")
    if not clean:
        return None
    try:
        r = requests.get(f"https://api.github.com/users/{clean}", timeout=4)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

def check_rdap_domain(email):
    if "@" not in email:
        return None
    domain = email.split("@")[1].lower()
    if domain in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]:
        return {"domain": domain, "type": "Free Webmail Provider"}
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=4)
        if r.status_code == 200:
            data = r.json()
            for ev in data.get("events", []):
                if ev.get("eventAction") == "registration":
                    return {"domain": domain, "registered": ev.get("eventDate", "")[:10]}
    except Exception:
        pass
    return {"domain": domain, "type": "Corporate Domain"}

def run_holehe_scan(email):
    """Runs Holehe CLI on backend to detect real registered accounts for an email."""
    found_sites = []
    try:
        proc = subprocess.run(
            ["holehe", email, "--only-used", "--no-color"],
            capture_output=True, text=True, timeout=25
        )
        for line in proc.stdout.splitlines():
            if line.startswith("[+]"):
                site = line.replace("[+]", "").strip()
                if site and "Email used" not in site:
                    found_sites.append(site)
    except Exception as e:
        pass
    return found_sites

# --- UI Header ---
st.title("🔍 AML & OSINT Account Discovery Engine")
st.caption("Backend-powered account probing, telecom intelligence (IN/US/CA), and entity verification.")

with st.form("osint_form"):
    c1, c2, c3, c4 = st.columns(4)
    email = c1.text_input("Email Address", placeholder="target@example.com")
    phone = c2.text_input("Phone Number", placeholder="+91 7034286564")
    person = c3.text_input("Individual Name / Handle", placeholder="Nayanesh Ck")
    business = c4.text_input("Business / Entity Name", placeholder="Infosys Limited")
    submitted = st.form_submit_button("Run Live Backend Investigation", use_container_width=True)

if submitted:
    if not any([email, phone, person, business]):
        st.warning("Enter at least one identifier to begin the backend scan.")
    else:
        with st.spinner("Probing live platforms, public APIs, and telecom registries..."):
            avatar_url = check_gravatar(email) if email else None
            gh_data = check_github_username(person) if person else None
            domain_info = check_rdap_domain(email) if email else None
            phone_loc = analyze_phone(phone) if phone else None
            holehe_hits = run_holehe_scan(email) if email else []

        st.success(f"Investigation complete — {len(holehe_hits) + (1 if gh_data else 0) + (1 if domain_info else 0)} live signals extracted.")

        # Top 3 Summary Cards (Matching your screenshot layout)
        s1, s2, s3 = st.columns(3)
        with s1:
            st.markdown('<div class="summary-card"><b>🖼️ Profile Pictures & Avatars</b></div>', unsafe_allow_html=True)
            if avatar_url:
                st.image(avatar_url, width=70, caption="Gravatar Match")
            if gh_data and gh_data.get("avatar_url"):
                st.image(gh_data["avatar_url"], width=70, caption=f"GitHub: {gh_data.get('login')}")
            if not avatar_url and not (gh_data and gh_data.get("avatar_url")):
                st.caption("No public avatar image exposed.")

        with s2:
            st.markdown('<div class="summary-card"><b>👤 Extracted Names & Handles</b></div>', unsafe_allow_html=True)
            if person:
                st.markdown(f'<span class="tag">{person}</span>', unsafe_allow_html=True)
            if gh_data and gh_data.get("name"):
                st.markdown(f'<span class="tag">{gh_data["name"]} (@{gh_data["login"]})</span>', unsafe_allow_html=True)
            if business:
                st.markdown(f'<span class="tag">{business}</span>', unsafe_allow_html=True)

        with s3:
            st.markdown('<div class="summary-card"><b>📞 Telecom & Location Intel</b></div>', unsafe_allow_html=True)
            if phone:
                st.markdown(f'<span class="tag">{phone}</span> <span class="tag">{phone_loc}</span>', unsafe_allow_html=True)
            if email:
                st.markdown(f'<span class="tag">{email}</span>', unsafe_allow_html=True)

        st.divider()
        st.subheader("Live Platform Matches")

        cols = st.columns(3)
        idx = 0

        # Render Holehe Live Account Discoveries
        for site in holehe_hits:
            with cols[idx % 3]:
                st.markdown(f"""
                <div class="result-card">
                    <div class="platform-badge">ACCOUNT REGISTERED • {site}</div>
                    <div class="target-title">{email}</div>
                    <div class="detail-text">Verified active registration via live endpoint probe.</div>
                </div>
                """, unsafe_allow_html=True)
            idx += 1

        # Render GitHub Live Profile Card
        if gh_data:
            with cols[idx % 3]:
                st.markdown(f"""
                <div class="result-card">
                    <div class="platform-badge">GITHUB • VERIFIED PROFILE</div>
                    <div class="target-title">{gh_data.get('name') or gh_data.get('login')} (@{gh_data.get('login')})</div>
                    <div class="detail-text">Location: {gh_data.get('location') or 'Not listed'}<br>
                    Public Repos: {gh_data.get('public_repos')} • Created: {gh_data.get('created_at', '')[:10]}<br>
                    <a href="{gh_data.get('html_url')}" target="_blank" style="color:#60a5fa;">Open Profile &rarr;</a></div>
                </div>
                """, unsafe_allow_html=True)
            idx += 1

        # Render Domain RDAP Intelligence Card
        if domain_info:
            with cols[idx % 3]:
                reg_text = f"Registered Date: {domain_info['registered']}" if "registered" in domain_info else domain_info.get("type", "")
                st.markdown(f"""
                <div class="result-card">
                    <div class="platform-badge">DOMAIN WHOIS / RDAP INTEL</div>
                    <div class="target-title">{domain_info['domain']}</div>
                    <div class="detail-text">{reg_text}<br>AML Check: Verify domain age against entity incorporation date.</div>
                </div>
                """, unsafe_allow_html=True)
            idx += 1

        if idx == 0:
            st.info("Tip: Enter a real email address (e.g., a personal Gmail) to see Holehe probe 120+ websites for active account registrations.")