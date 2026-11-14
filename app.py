import streamlit as st
import requests
import hashlib
import subprocess
import re
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
        min-height: 155px;
    }
    .platform-badge {
        font-size: 11px; font-weight: 700; color: #3b82f6;
        text-transform: uppercase; letter-spacing: 0.6px;
    }
    .badge-live { color: #10b981; }
    .target-title { font-size: 16px; font-weight: 600; color: #ffffff; margin: 6px 0; word-break: break-word; }
    .detail-text { font-size: 13px; color: #b0b0b0; line-height: 1.45; }
    .tag {
        display: inline-block; background: #2c2c2c; color: #e0e0e0;
        padding: 4px 10px; border-radius: 4px; font-size: 12px; margin: 3px 2px;
    }
    a.card-link { color: #60a5fa; text-decoration: none; font-weight: 600; font-size: 12px; }
    a.card-link:hover { text-decoration: underline; }
</style>
""", unsafe_allow_html=True)

# India, US & Canada Telecom Prefix Database
AREA_CODES = {
    "416": "Toronto, Ontario, Canada 🇨🇦", "647": "Toronto, Ontario, Canada 🇨🇦", "437": "Toronto, Ontario, Canada 🇨🇦",
    "613": "Ottawa, Ontario, Canada 🇨🇦", "514": "Montreal, Quebec, Canada 🇨🇦", "604": "Vancouver, BC, Canada 🇨🇦",
    "403": "Calgary, Alberta, Canada 🇨🇦", "780": "Edmonton, Alberta, Canada 🇨🇦",
    "212": "New York City, NY, USA 🇺🇸", "646": "New York City, NY, USA 🇺🇸", "415": "San Francisco, CA, USA 🇺🇸",
    "310": "Los Angeles, CA, USA 🇺🇸", "312": "Chicago, IL, USA 🇺🇸", "305": "Miami, FL, USA 🇺🇸",
    "202": "Washington, D.C., USA 🇺🇸", "206": "Seattle, WA, USA 🇺🇸", "302": "Delaware (Corporate Hub), USA 🇺🇸"
}

INDIA_SERIES = {
    "9840": "Airtel - Chennai / TN, India 🇮🇳", "9444": "BSNL - Chennai, India 🇮🇳",
    "9845": "Airtel - Karnataka, India 🇮🇳", "9820": "Vi - Mumbai, India 🇮🇳",
    "9810": "Airtel - Delhi NCR, India 🇮🇳", "7012": "Jio - Kerala, India 🇮🇳",
    "7034": "Jio - Kerala, India 🇮🇳", "9447": "BSNL - Kerala, India 🇮🇳",
    "9895": "Airtel - Kerala, India 🇮🇳"
}

def analyze_phone(raw_phone):
    digits = re.sub(r"[^0-9]", "", raw_phone)
    if not digits:
        return None
    if digits.startswith("91") and len(digits) == 12:
        local = digits[2:]
        return {"country": "India 🇮🇳", "region": INDIA_SERIES.get(local[:4], "India Mobile Network (+91)"), "clean": f"+91{local}", "local": local}
    if len(digits) == 10 and digits[0] in "6789" and not raw_phone.strip().startswith("+1"):
        return {"country": "India 🇮🇳", "region": INDIA_SERIES.get(digits[:4], "India Mobile Network (+91)"), "clean": f"+91{digits}", "local": digits}
    if (digits.startswith("1") and len(digits) == 11) or (len(digits) == 10 and raw_phone.strip().startswith("+1")):
        local = digits[1:] if len(digits) == 11 else digits
        loc = AREA_CODES.get(local[:3], "North America (US / Canada +1)")
        flag = "Canada 🇨🇦" if "Canada" in loc else ("United States 🇺🇸" if "USA" in loc else "US / Canada 🇺🇸🇨🇦")
        return {"country": flag, "region": loc, "clean": f"+1{local}", "local": local}
    return {"country": "International 🌍", "region": f"Country Prefix +{digits[:2]}", "clean": f"+{digits}", "local": digits}

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

def search_github_people(name_or_handle):
    """Searches GitHub both by exact handle AND by full name."""
    results = []
    clean_handle = re.sub(r"[^a-zA-Z0-9-]", "", name_or_handle.strip())
    headers = {"Accept": "application/vnd.github.v3+json"}
    try:
        # 1. Exact handle lookup
        if clean_handle:
            r1 = requests.get(f"https://api.github.com/users/{clean_handle}", headers=headers, timeout=5)
            if r1.status_code == 200:
                results.append(r1.json())
        # 2. Full-name user search if not already found
        if not results:
            r2 = requests.get(f"https://api.github.com/search/users?q={quote_plus(name_or_handle)}&per_page=3", headers=headers, timeout=5)
            if r2.status_code == 200:
                items = r2.json().get("items", [])
                for item in items[:2]:
                    detail = requests.get(item["url"], headers=headers, timeout=4)
                    if detail.status_code == 200:
                        results.append(detail.json())
    except Exception:
        pass
    return results

def search_wikipedia_entity(query):
    """Checks Wikipedia public API for PEP / Public Figure / Corporate background."""
    try:
        url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{quote_plus(query.strip().replace(' ', '_'))}"
        r = requests.get(url, headers={"User-Agent": "AML-OSINT-Workbench/1.0"}, timeout=5)
        if r.status_code == 200:
            data = r.json()
            if data.get("type") == "standard":
                return {
                    "title": data.get("title"),
                    "extract": data.get("extract", "")[:220] + "...",
                    "url": data.get("content_urls", {}).get("desktop", {}).get("page", ""),
                    "thumbnail": data.get("thumbnail", {}).get("source")
                }
    except Exception:
        pass
    return None

def search_gleif_lei(company_name):
    """Queries the official free GLEIF Global Legal Entity Identifier API."""
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
                    return {"domain": domain, "info": f"Registered: {ev.get('eventDate', '')[:10]}"}
    except Exception:
        pass
    return {"domain": domain, "info": "Corporate / Private Domain"}

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

# --- UI ---
st.title("🔍 AML & OSINT Account Discovery Engine")
st.caption("Enter ANY single identifier (Email, Phone, Individual Name, or Business Name) to run live backend intelligence.")

with st.form("osint_form"):
    c1, c2, c3, c4 = st.columns(4)
    email = c1.text_input("Email Address", placeholder="Optional (e.g., user@gmail.com)")
    phone = c2.text_input("Phone Number", placeholder="Optional (e.g., +917012284986)")
    person = c3.text_input("Individual Name / Handle", placeholder="Optional (e.g., Nayanesh Ck)")
    business = c4.text_input("Business / Entity Name", placeholder="Optional (e.g., Infosys)")
    submitted = st.form_submit_button("Run Live Backend Investigation", use_container_width=True)

if submitted:
    if not any([email.strip(), phone.strip(), person.strip(), business.strip()]):
        st.warning("Please enter at least one field (Email, Phone Number, Individual Name, or Business Name).")
    else:
        cards = []  # List of dicts: {badge, live, title, detail, link_text, link_url}
        avatars = []

        with st.spinner("Running live backend checks across APIs, registries, and social endpoints..."):
            # 1. EMAIL MODULE
            if email.strip():
                em = email.strip()
                av = check_gravatar(em)
                if av:
                    avatars.append((av, "Gravatar Profile"))
                dom = check_rdap_domain(em)
                if dom:
                    cards.append({
                        "badge": "DOMAIN RDAP INTEL", "live": True, "title": dom["domain"],
                        "detail": f"{dom['info']}<br>AML Check: Compare domain age against onboarding history.",
                        "link_text": "Inspect Full WHOIS →", "link_url": f"https://who.is/whois/{quote_plus(dom['domain'])}"
                    })
                hits = run_holehe_scan(em)
                for site in hits:
                    cards.append({
                        "badge": f"LIVE ACCOUNT • {site}", "live": True, "title": em,
                        "detail": f"Active registration confirmed on <b>{site}</b> via backend probe.",
                        "link_text": "", "link_url": ""
                    })
                # Social & Leak Pivots for Email
                q_em = quote_plus(f'"{em}"')
                cards.append({
                    "badge": "SOCIAL & WEB GRAPH", "live": False, "title": em,
                    "detail": "Cross-check LinkedIn, Instagram, Facebook, X & public document leaks.",
                    "link_text": "Open Social Footprint →", "link_url": f"https://www.google.com/search?q={q_em}+site:linkedin.com+OR+site:instagram.com+OR+site:facebook.com+OR+site:x.com"
                })

            # 2. PHONE NUMBER MODULE
            phone_meta = None
            if phone.strip():
                ph = phone.strip()
                phone_meta = analyze_phone(ph)
                q_ph = quote_plus(f'"{ph}" OR "{phone_meta["clean"]}" OR "{phone_meta["local"]}"')
                cards.append({
                    "badge": f"TELECOM INTEL • {phone_meta['country']}", "live": True, "title": ph,
                    "detail": f"<b>Region/Carrier:</b> {phone_meta['region']}<br><b>E.164 Standard:</b> {phone_meta['clean']}",
                    "link_text": "Trace Number on Web →", "link_url": f"https://www.google.com/search?q={q_ph}"
                })
                cards.append({
                    "badge": "SOCIAL & MESSAGING TRACE", "live": False, "title": ph,
                    "detail": "Search linked WhatsApp links, Facebook, LinkedIn & B2B directory listings.",
                    "link_text": "Check Linked Profiles →", "link_url": f"https://www.google.com/search?q={q_ph}+site:facebook.com+OR+site:linkedin.com+OR+site:instagram.com+OR+site:justdial.com+OR+site:indiamart.com"
                })

            # 3. INDIVIDUAL NAME / HANDLE MODULE
            if person.strip():
                nm = person.strip()
                gh_users = search_github_people(nm)
                for gh in gh_users:
                    if gh.get("avatar_url"):
                        avatars.append((gh["avatar_url"], f"GitHub: {gh.get('login')}"))
                    cards.append({
                        "badge": "GITHUB • LIVE ACCOUNT", "live": True,
                        "title": f"{gh.get('name') or gh.get('login')} (@{gh.get('login')})",
                        "detail": f"<b>Location:</b> {gh.get('location') or 'N/A'} | <b>Repos:</b> {gh.get('public_repos')}<br><b>Bio:</b> {gh.get('bio') or 'No bio'}",
                        "link_text": "Open GitHub Profile →", "link_url": gh.get("html_url", "")
                    })

                wiki = search_wikipedia_entity(nm)
                if wiki:
                    if wiki.get("thumbnail"):
                        avatars.append((wiki["thumbnail"], wiki["title"]))
                    cards.append({
                        "badge": "PUBLIC FIGURE / PEP INTEL", "live": True, "title": wiki["title"],
                        "detail": wiki["extract"],
                        "link_text": "Read Full Background →", "link_url": wiki["url"]
                    })

                q_nm = quote_plus(f'"{nm}"')
                cards.append({
                    "badge": "LINKEDIN PROFILE RECON", "live": False, "title": nm,
                    "detail": "Verify employment history, current employer, directorships & education.",
                    "link_text": "Search LinkedIn →", "link_url": f"https://www.google.com/search?q={q_nm}+site:linkedin.com/in/"
                })
                cards.append({
                    "badge": "META & X SOCIAL FOOTPRINT", "live": False, "title": nm,
                    "detail": "Scan Instagram, Facebook & X/Twitter handles and tagged connections.",
                    "link_text": "Search Social Handles →", "link_url": f"https://www.google.com/search?q={q_nm}+site:instagram.com+OR+site:facebook.com+OR+site:x.com"
                })
                cards.append({
                    "badge": "OPENSANCTIONS & PEP SCREEN", "live": False, "title": nm,
                    "detail": "Screen against global OFAC/EU/UN sanctions, watchlists & PEP registries.",
                    "link_text": "Screen OpenSanctions →", "link_url": f"https://www.opensanctions.org/search/?q={quote_plus(nm)}"
                })

            # 4. BUSINESS / ENTITY MODULE
            if business.strip():
                biz = business.strip()
                lei_hits = search_gleif_lei(biz)
                for rec in lei_hits:
                    cards.append({
                        "badge": f"GLEIF LEI REGISTRY • {rec['status']}", "live": True, "title": rec["name"],
                        "detail": f"<b>LEI Code:</b> {rec['lei']}<br><b>Jurisdiction:</b> {rec['jurisdiction']} ({rec['city']}, {rec['country']})",
                        "link_text": "Verify LEI Record →", "link_url": f"https://search.gleif.org/#/record/{rec['lei']}"
                    })

                q_biz = quote_plus(f'"{biz}"')
                cards.append({
                    "badge": "CORPORATE REGISTRIES (IN/US/CA/GLOBAL)", "live": False, "title": biz,
                    "detail": "Check MCA/ZaubaCorp (India), SEC EDGAR (US), Corporations Canada & OpenCorporates.",
                    "link_text": "Search Corporate Filings →", "link_url": f"https://www.google.com/search?q={q_biz}+site:zaubacorp.com+OR+site:sec.gov+OR+site:opencorporates.com+OR+site:ised-isde.canada.ca"
                })
                cards.append({
                    "badge": "ICIJ OFFSHORE & ADVERSE MEDIA", "live": False, "title": biz,
                    "detail": "Screen Panama/Pandora Papers offshore leaks and global regulatory enforcement news.",
                    "link_text": "Check ICIJ Leaks →", "link_url": f"https://offshoreleaks.icij.org/search?q={quote_plus(biz)}"
                })

        st.success(f"Investigation complete — {len(cards)} intelligence modules executed.")

        # Top Summary Row
        s1, s2, s3 = st.columns(3)
        with s1:
            st.markdown('<div class="summary-card"><b>🖼️ Profile Pictures & Avatars</b></div>', unsafe_allow_html=True)
            if avatars:
                img_cols = st.columns(min(len(avatars), 3))
                for i, (img_url, cap) in enumerate(avatars[:3]):
                    img_cols[i].image(img_url, width=65, caption=cap)
            else:
                st.caption("No public avatar image exposed.")

        with s2:
            st.markdown('<div class="summary-card"><b>👤 Target Identifiers</b></div>', unsafe_allow_html=True)
            if person.strip():
                st.markdown(f'<span class="tag">{person.strip()}</span>', unsafe_allow_html=True)
            if business.strip():
                st.markdown(f'<span class="tag">{business.strip()}</span>', unsafe_allow_html=True)
            if not person.strip() and not business.strip():
                st.caption("No name/entity entered.")

        with s3:
            st.markdown('<div class="summary-card"><b>📞 Telecom & Contact Intel</b></div>', unsafe_allow_html=True)
            if phone_meta:
                st.markdown(f'<span class="tag">{phone.strip()}</span> <span class="tag">{phone_meta["region"]}</span>', unsafe_allow_html=True)
            if email.strip():
                st.markdown(f'<span class="tag">{email.strip()}</span>', unsafe_allow_html=True)
            if not phone_meta and not email.strip():
                st.caption("No phone/email entered.")

        st.divider()
        st.subheader(f"Intelligence Findings ({len(cards)})")

        cols = st.columns(3)
        for i, card in enumerate(cards):
            badge_class = "platform-badge badge-live" if card["live"] else "platform-badge"
            link_html = f'<br><br><a class="card-link" href="{card["link_url"]}" target="_blank">{card["link_text"]}</a>' if card["link_url"] else ""
            with cols[i % 3]:
                st.markdown(f"""
                <div class="result-card">
                    <div class="{badge_class}">{card['badge']}</div>
                    <div class="target-title">{card['title']}</div>
                    <div class="detail-text">{card['detail']}{link_html}</div>
                </div>
                """, unsafe_allow_html=True)
