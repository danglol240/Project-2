import sys
import pickle
import requests
import base64

def sanitization(web):
    web = web.lower()
    token = []
    dot_token_slash = []
    raw_slash = str(web).split('/')
    for i in raw_slash:
        raw1 = str(i).split('-')
        slash_token = []
        for j in range(0,len(raw1)):
            raw2 = str(raw1[j]).split('.')
            slash_token = slash_token + raw2
        dot_token_slash = dot_token_slash + raw1 + slash_token
    token = list(set(dot_token_slash)) 
    if 'com' in token:
        token.remove('com')
    return token

if len(sys.argv) < 3:
    print("⚠️ Vui lòng cung cấp URL và API Key.")
    sys.exit(1)

url = sys.argv[1].strip().lower()
api_key = sys.argv[2].strip()

def url_to_vt_id(url):
    url_bytes = url.encode()
    vt_id = base64.urlsafe_b64encode(url_bytes).decode().strip("=")
    return vt_id

# Bước 1: Dự đoán bằng model
try:
    with open("Classifier/pickel_model.pkl", "rb") as f:
        model = pickle.load(f)
    with open("Classifier/pickel_vector.pkl", "rb") as f:
        vectorizer = pickle.load(f)
    x = vectorizer.transform([url])
    prediction = model.predict(x)[0]
    label = '✅ benign' if prediction == 'benign' else '🔥 malicious'
    print(f"🔍 Kết quả từ mô hình ML: {label}")
except Exception as e:
    print(f"❌ Lỗi khi dự đoán bằng mô hình: {e}")

# Bước 2: Gửi URL đến VirusTotal và lấy kết quả phân tích
try:
    # Gửi URL để lấy analysis_id
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers={"x-apikey": api_key},
        data={"url": url}
    )
    
    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        # Lấy báo cáo phân tích
        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers={"x-apikey": api_key}
        )
        if report.status_code == 200:
            data = report.json()["data"]["attributes"]["stats"]
            harmless = data.get("harmless", 0)
            malicious = data.get("malicious", 0)
            suspicious = data.get("suspicious", 0)
            undetected = data.get("undetected", 0)
            total = harmless + malicious + suspicious + undetected
            print(f"\n🌐 VirusTotal: Kết quả phân tích:")
            print(f"  - Harmless: {harmless}")
            print(f"  - Malicious: {malicious}")
            print(f"  - Suspicious: {suspicious}")
            print(f"  - Undetected: {undetected}")
            print(f"  - Tổng số engine: {total}")
            vt_id = url_to_vt_id(url)
            vt_link = f"https://www.virustotal.com/gui/url/{vt_id}"
            print(f"🔗 Xem chi tiết tại: {vt_link}")
        else:
            print(f"❌ Lỗi lấy báo cáo VirusTotal: {report.status_code}\n{report.text}")
    else:
        print(f"❌ VirusTotal gửi thất bại: {response.status_code}\n{response.text}")
except Exception as e:
    print(f"❌ Lỗi gửi hoặc lấy kết quả VirusTotal: {e}")
