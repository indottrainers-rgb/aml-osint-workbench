import streamlit as st
import requests
import hashlib
import subprocess
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from urllib.parse import quote_plus

st.set_page_config(page_title="AML OSINT Intelligence Engine", page_icon="🔍", layout="wide")

st.markdown("""
<style>
    .stApp { background-color: #121212; color: #e0e0e0; }
    .summary-card {
        background-color: #1e1e1e; border: 1px solid #2c2c2c;
        border-radius: 8px; padding: 14px; margin-bottom: 12px;
    }
    .result-card {
        background-color: #1e1e1e; border: 1px solid #2c2c2c;
        border-radius: 8px; padding: 18px; margin-bottom: 14px;
        min-height: 150px;
    }
    .platform-badge {
        font-size: 11px; font-weight: 700; color: #10b981;
        text-transform: uppercase; letter-spacing: 0.6px;
    }
    .target-title { font-size: 16px; font-weight: 600; color: #ffffff; margin: 6px 0; word-break: break-word; }
    .detail-text { font-size: 13px; color: #b0b0b0; line-height: 1.5; }
    .tag {
        display: inline-block; background: #2c2c2c; color: #e0e0e0;
        padding: 4px 10px; border-radius: 4px; font-size: 12px; margin: 3px 2px;
    }
    a.card-link { color: #60a5fa; text-decoration: none; font-weight: 600; font-size: 12px; }
</style>
""", unsafe_allow_html=True)

def analyze_phone_live(raw_phone):
    """Uses Google's libphonenumber to extract exact global telecom metadata."""
    try:
        cleaned = raw_phone.strip()
        if not cleaned.startswith("+"):
            cleaned = "+" + cleaned
        parsed = phonenumbers.parse(cleaned, None)
        if not phonenumbers.is_valid_number(parsed):
            return None
        region = geocoder.description_for_number(parsed, "en") or "Unknown Region"
        op = carrier.name_for_number(parsed, "en") or "Standard Carrier"
        tz = ", ".join(timezone.time_zones_for_number(parsed)) or "Unknown"
        num_type = "Mobile" if phonenumbers.number_type(parsed) == phonenumbers.PhoneNumberType.MOBILE else "Fixed / VoIP"
        return {
            "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "intl": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "country_code": f"+{parsed.country_code}",
            "region": region,
            "carrier": op,
            "timezone": tz,
            "type": num_type
        }
    except Exception:
        return None

def run_ignorant_phone_check(country_code, national_num):
    """Probes supported platforms via Ignorant CLI to check if phone number is registered."""
    found = []
    try:
        proc = subprocess.run(
            ["ignorant", country_code.replace("+", ""), national_num, "--only-used", "--no-color"],
            capture_output=True, text=True, timeout=20
        )
        for line in proc.stdout.splitlines():
            if line.startswith("[+]"):
                site = line.replace("[+]", "").strip()
                if site and "Phone number used" not in site:
                    found.append(site)
    except Exception:
        pass
    return found

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

def check_rdap_domain(email):
    if "@" not in email:
        return None
    domain = email.split("@")[1].lower()
    if domain in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com"]:
        return {"domain": domain, "info": "Consumer Webmail Provider"}
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=4)
        if r.status_code == 200:
            for ev in r.json().get("events", []):
                if ev.get("eventAction") == "registration":
                    return {"domain": domain, "info": f"Registered Date: {ev.get('eventDate', '')[:10]}"}
    except Exception:
        pass
    return {"domain": domain, "info": "Private / Corporate Domain"}

def run_holehe_scan(email):
    found_sites = []
    try:
        proc = subprocess.run(["holehe", email, "--only-used", "--no-color"], capture_output=True, text=True, timeout=25)
        for line in proc.stdout.splitlines():
            if line.startswith("[+]"):
                site = line.replace("[+]", "").strip()
                if site and "Email used" not in site:
                    found_sites.append(site)
    except Exception:
        pass
    return found_sites

def search_github_people(name_or_handle):
    results = []
    headers = {"Accept": "application/vnd.github.v3+json"}
    try:
        r = requests.get(f"https://api.github.com/search/users?q={quote_plus(name_or_handle)}&per_page=3", headers=headers, timeout=5)
        if r.status_code == 200:
            for item in r.json().get("items", [])[:3]:
                detail = requests.get(item["url"], headers=headers, timeout=4)
                if detail.status_code == 200:
                    results.append(detail.json())
    except Exception:
        pass
    return results

def search_wikipedia_entity(query):
    try:
        url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{quote_plus(query.strip().replace(' ', '_'))}"
        r = requests.get(url, headers={"User-Agent": "AML-OSINT-Workbench/1.0"}, timeout=5)
        if r.status_code == 200:
            data = r.json()
            if data.get("type") == "standard":
                return {
                    "title": data.get("title"),
                    "extract": data.get("extract", "")[:240] + "...",
                    "url": data.get("content_urls", {}).get("desktop", {}).get("page", ""),
                    "thumbnail": data.get("thumbnail", {}).get("source")
                }
    except Exception:
        pass
    return None

def search_gleif_lei(company_name):
    try:
        url = f"https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]={quote_plus(company_name)}&page[size]=3"
        r = requests.get(url, timeout=6)
        if r.status_code == 200:
            records = []
            for item in r.json().get("data", []):
                attrs = item.get("attributes", {})
                ent = attrs.get("entity", {})
                addr = ent.get("legalAddress", {})
                records.append({
                    "lei": attrs.get("lei"),
                    "name": ent.get("legalName", {}).get("name"),
                    "status": ent.get("status"),
                    "jurisdiction": ent.get("jurisdiction"),
                    "city": addr.get("city", ""),
                    "country": addr.get("country", "")
                })
            return records
    except Exception:
        pass
    return []

# --- UI ---
st.title("🔍 AML & OSINT Direct Data Engine")
st.caption("Zero search-engine redirects — extracts live structured data from open APIs, telecom registries, and endpoint probes.")

with st.form("osint_form"):
    c1, c2, c3, c4 = st.columns(4)
    email = c1.text_input("Email Address", placeholder="e.g., user@gmail.com")
    phone = c2.text_input("Phone Number (with + code)", placeholder="e.g., +917012284986")
    person = c3.text_input("Individual Name / Handle", placeholder="e.g., Sundar Pichai")
    business = c4.text_input("Business / Entity Name", placeholder="e.g., Infosys Limited")
    submitted = st.form_submit_button("Extract Live Intelligence", use_container_width=True)

if submitted:
    if not any([email.strip(), phone.strip(), person.strip(), business.strip()]):
        st.warning("Enter at least one identifier (Email, Phone, Name, or Business).")
    else:
        cards = []
        avatars = []

        with st.spinner("Querying live public APIs, telecom metadata, and endpoint probes..."):
            # 1. EMAIL
            if email.strip():
                em = email.strip()
                av = check_gravatar(em)
                if av:
                    avatars.append((av, "Gravatar Avatar"))
                dom = check_rdap_domain(em)
                if dom:
                    cards.append({
                        "badge": "DOMAIN RDAP RECORD",
                        "title": dom["domain"],
                        "detail": f"{dom['info']}<br>Source: Official RDAP Registry",
                        "link_text": "", "link_url": ""
                    })
                for site in run_holehe_scan(em):
                    cards.append({
                        "badge": f"ACTIVE ACCOUNT • {site}",
                        "title": em,
                        "detail": f"Verified active registration on <b>{site}</b> via password-reset endpoint probe.",
                        "link_text": "", "link_url": ""
                    })

            # 2. PHONE
            phone_meta = None
            if phone.strip():
                ph = phone.strip()
                phone_meta = analyze_phone_live(ph)
                if phone_meta:
                    cards.append({
                        "badge": f"TELECOM METADATA • {phone_meta['type']}",
                        "title": phone_meta["intl"],
                        "detail": f"<b>Region/Country:</b> {phone_meta['region']}<br><b>Original Carrier:</b> {phone_meta['carrier']}<br><b>Timezone:</b> {phone_meta['timezone']}",
                        "link_text": "", "link_url": ""
                    })
                    national_digits = phone_meta["e164"].replace(phone_meta["country_code"], "")
                    for site in run_ignorant_phone_check(phone_meta["country_code"], national_digits):
                        cards.append({
                            "badge": f"PHONE ACCOUNT • {site}",
                            "title": phone_meta["intl"],
                            "detail": f"Phone number confirmed registered on <b>{site}</b>.",
                            "link_text": "", "link_url": ""
                        })
                else:
                    st.error("Invalid phone format. Include country code (e.g., +917012284986 or +14165550199).")

            # 3. INDIVIDUAL NAME
            if person.strip():
                nm = person.strip()
                for gh in search_github_people(nm):
                    if gh.get("avatar_url"):
                        avatars.append((gh["avatar_url"], f"GitHub: {gh.get('login')}"))
                    cards.append({
                        "badge": "GITHUB • LIVE PROFILE",
                        "title": f"{gh.get('name') or gh.get('login')} (@{gh.get('login')})",
                        "detail": f"<b>Location:</b> {gh.get('location') or 'Not listed'} | <b>Repos:</b> {gh.get('public_repos')}<br><b>Bio:</b> {gh.get('bio') or 'No bio'}",
                        "link_text": "View Direct Profile →", "link_url": gh.get("html_url", "")
                    })

                wiki = search_wikipedia_entity(nm)
                if wiki:
                    if wiki.get("thumbnail"):
                        avatars.append((wiki["thumbnail"], wiki["title"]))
                    cards.append({
                        "badge": "ENTITY / PEP KNOWLEDGE GRAPH",
                        "title": wiki["title"],
                        "detail": wiki["extract"],
                        "link_text": "View Source Record →", "link_url": wiki["url"]
                    })

            # 4. BUSINESS NAME
            if business.strip():
                biz = business.strip()
                for rec in search_gleif_lei(biz):
                    cards.append({
                        "badge": f"GLEIF LEI REGISTRY • {rec['status']}",
                        "title": rec["name"],
                        "detail": f"<b>LEI:</b> {rec['lei']}<br><b>Jurisdiction:</b> {rec['jurisdiction']} ({rec['city']}, {rec['country']})",
                        "link_text": "View Official LEI Record →", "link_url": f"https://search.gleif.org/#/record/{rec['lei']}"
                    })

        st.success(f"Extraction complete — {len(cards)} verified data records returned.")

        s1, s2, s3 = st.columns(3)
        with s1:
            st.markdown('<div class="summary-card"><b>🖼️ Extracted Avatars</b></div>', unsafe_allow_html=True)
            if avatars:
                img_cols = st.columns(min(len(avatars), 3))
                for i, (img_url, cap) in enumerate(avatars[:3]):
                    img_cols[i].image(img_url, width=65, caption=cap)
            else:
                st.caption("No public avatar returned.")

        with s2:
            st.markdown('<div class="summary-card"><b>👤 Target Identifiers</b></div>', unsafe_allow_html=True)
            if person.strip():
                st.markdown(f'<span class="tag">{person.strip()}</span>', unsafe_allow_html=True)
            if business.strip():
                st.markdown(f'<span class="tag">{business.strip()}</span>', unsafe_allow_html=True)
            if not person.strip() and not business.strip():
                st.caption("None entered.")

        with s3:
            st.markdown('<div class="summary-card"><b>📞 Telecom & Contact</b></div>', unsafe_allow_html=True)
            if phone_meta:
                st.markdown(f'<span class="tag">{phone_meta["intl"]}</span> <span class="tag">{phone_meta["region"]}</span> <span class="tag">{phone_meta["carrier"]}</span>', unsafe_allow_html=True)
            if email.strip():
                st.markdown(f'<span class="tag">{email.strip()}</span>', unsafe_allow_html=True)
            if not phone_meta and not email.strip():
                st.caption("None entered.")

        st.divider()
        st.subheader(f"Verified Intelligence Records ({len(cards)})")

        if cards:
            cols = st.columns(3)
            for i, card in enumerate(cards):
                link_html = f'<br><br><a class="card-link" href="{card["link_url"]}" target="_blank">{card["link_text"]}</a>' if card["link_url"] else ""
                with cols[i % 3]:
                    st.markdown(f"""
                    <div class="result-card">
                        <div class="platform-badge">{card['badge']}</div>
                        <div class="target-title">{card['title']}</div>
                        <div class="detail-text">{card['detail']}{link_html}</div>
                    </div>
                    """, unsafe_allow_html=True)
        else:
            st.info("No public records found in free open APIs for that exact input. Try an active email address, a global company name (e.g., Infosys), or a public figure/GitHub username.")
