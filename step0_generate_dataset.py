"""
STEP 0: Generate a synthetic phishing URL dataset for development.
=====================================================================
WHY THIS EXISTS:

- This script creates a realistic fake dataset so you can develop
  and test your code RIGHT NOW.
  
WHAT IT CREATES:
- 10,000 URLs (5,000 phishing + 5,000 legitimate)
- Each URL is labeled: 1 = phishing, 0 = legitimate

"""

import random
import csv
import os

random.seed(42)  # Makes results reproducible

# === Building blocks for fake URLs ===

# Legit domains look normal
legit_domains = [
    "google.com", "facebook.com", "amazon.com", "microsoft.com",
    "apple.com", "netflix.com", "github.com", "stackoverflow.com",
    "wikipedia.org", "linkedin.com", "twitter.com", "instagram.com",
    "youtube.com", "reddit.com", "ebay.com", "walmart.com",
    "bbc.co.uk", "cnn.com", "nytimes.com", "medium.com",
    "shopify.com", "dropbox.com", "zoom.us", "slack.com",
    "adobe.com", "spotify.com", "paypal.com", "chase.com",
    "bankofamerica.com", "wellsfargo.com", "td.com", "rbc.ca",
]

legit_paths = [
    "/", "/about", "/contact", "/products", "/services",
    "/help", "/support", "/login", "/account", "/settings",
    "/news", "/blog", "/docs", "/api", "/pricing",
    "/careers", "/team", "/faq", "/terms", "/privacy",
]

# Phishing domains look suspicious
phishing_keywords = [
    "secure", "verify", "update", "confirm", "login",
    "account", "banking", "signin", "authenticate", "validate",
    "password", "credential", "alert", "suspended", "locked",
]

phishing_brands = [
    "paypal", "apple", "google", "microsoft", "amazon",
    "netflix", "chase", "wellsfargo", "bankofamerica", "facebook",
    "instagram", "linkedin", "dropbox", "adobe", "spotify",
]

phishing_tlds = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".top", ".club", ".online", ".site", ".info",
    ".ru", ".cn", ".buzz", ".link", ".click",
]

phishing_paths = [
    "/verify-account", "/secure-login", "/update-info",
    "/confirm-identity", "/reset-password", "/unlock-account",
    "/validate-user", "/security-check", "/auth/login",
    "/account/verify", "/signin/confirm", "/secure/update",
]


def generate_legit_url():
    """Generate a realistic legitimate URL."""
    protocol = random.choice(["https://", "https://www."])
    domain = random.choice(legit_domains)
    path = random.choice(legit_paths)
    
    # Sometimes add a subdomain
    if random.random() < 0.1:
        subdomain = random.choice(["blog", "docs", "help", "api", "mail"])
        domain = f"{subdomain}.{domain}"
    
    # Sometimes add query parameters
    query = ""
    if random.random() < 0.2:
        query = f"?id={random.randint(100, 9999)}"
    
    return protocol + domain + path + query


def generate_phishing_url():
    """Generate a realistic phishing URL."""
    protocol = random.choice(["http://", "https://", "http://www."])
    
   
    pattern = random.choice(["keyword_combo", "brand_fake", "ip_based", "long_subdomain"])
    
    if pattern == "keyword_combo":
        # e.g., secure-paypal-login.xyz
        parts = random.sample(phishing_keywords, random.randint(2, 3))
        brand = random.choice(phishing_brands)
        sep = random.choice(["-", ".", ""])
        domain = sep.join(parts + [brand]) + random.choice(phishing_tlds)
        
    elif pattern == "brand_fake":
      
        brand = random.choice(phishing_brands)
        keyword = random.choice(phishing_keywords)
        fake_ext = random.choice([".com", ".org", ".net"])
        domain = f"{brand}-{keyword}{fake_ext}.{keyword}-{random.choice(phishing_keywords)}{random.choice(phishing_tlds)}"
        
    elif pattern == "ip_based":
        # e.g., http://192.168.1.100/paypal/login
        ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"
        brand = random.choice(phishing_brands)
        return f"http://{ip}/{brand}/login"
        
    elif pattern == "long_subdomain":
        # e.g., paypal.com.secure.verify.evil.xyz
        brand = random.choice(phishing_brands)
        subs = random.sample(phishing_keywords, random.randint(2, 4))
        domain = f"{brand}.com.{'.'.join(subs)}{random.choice(phishing_tlds)}"
    
    path = random.choice(phishing_paths)
    
    # Sometimes add suspicious query params
    query = ""
    if random.random() < 0.4:
        query = f"?token={random.randint(100000, 999999)}&redirect=true"
    
    return protocol + domain + path + query


# === Generate the dataset ===
print("Generating dataset...")

urls_data = []

# Generate 5000 legitimate URLs
for _ in range(5000):
    url = generate_legit_url()
    urls_data.append({"url": url, "label": 0})  # 0 = legitimate

# Generate 5000 phishing URLs
for _ in range(5000):
    url = generate_phishing_url()
    urls_data.append({"url": url, "label": 1})  # 1 = phishing

# Shuffle so they're mixed up
random.shuffle(urls_data)

# Save to CSV
output_path = os.path.join(os.path.dirname(__file__), "dataset", "urls.csv")
with open(output_path, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["url", "label"])
    writer.writeheader()
    writer.writerows(urls_data)

print(f"Done! Created {len(urls_data)} URLs")
print(f"  - Legitimate (label=0): {sum(1 for d in urls_data if d['label'] == 0)}")
print(f"  - Phishing   (label=1): {sum(1 for d in urls_data if d['label'] == 1)}")
print(f"  - Saved to: {output_path}")

# Show a few examples
print("\nSample legitimate URLs:")
for d in urls_data:
    if d["label"] == 0:
        print(f"  {d['url']}")
        break
        
print("\nSample phishing URLs:")
for d in urls_data:
    if d["label"] == 1:
        print(f"  {d['url']}")
        break
