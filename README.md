# Scanner.py
#!/usr/bin/env python3
import requests
import sys

def check_vulnerability(url):
    try:
        headers = {"x-middleware-subrequest": "1", "User-Agent": "Mozilla/5.0"}
        
        # تست مسیرهای حساس
        sensitive_paths = ["/admin", "/dashboard", "/control"]
        
        for path in sensitive_paths:
            target_url = url.rstrip('/') + path
            
            try:
                # درخواست عادی (بدون هدر ویژه)
                normal_res = requests.head(target_url, timeout=5, allow_redirects=False)
                
                # اگر دسترسی ممنوع بود، با هدر ویژه تست می‌کنیم
                if normal_res.status_code in [401, 403]:
                    vuln_res = requests.head(target_url, headers=headers, timeout=5, allow_redirects=False)
                    
                    if vuln_res.status_code == 200:
                        return True, f"نشت دسترسی! مسیر {target_url} با هدر ویژه قابل دسترسی است."
            
            except requests.exceptions.RequestException:
                continue
                
        return False, "آسیب‌پذیری تأیید نشد"
    
    except Exception as e:
        return False, f"خطا: {str(e)}"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("طریقه استفاده: python3 scanner.py <آدرس سایت یا فایل txt>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if target.startswith(('http://', 'https://')):
        # تست تک سایت
        result, message = check_vulnerability(target)
        print(f"\nنتایج برای {target}:")
        print("=" * 50)
        print(f"وضعیت: {message}")
    else:
        # پردازش فایل حاوی لیست URLها
        try:
            with open(target, 'r') as f:
                print("\nشروع اسکن...")
                print("=" * 50)
                for line in f:
                    url = line.strip()
                    if url:
                        result, message = check_vulnerability(url)
                        if result:
                            print(f"[!] آسیب‌پذیر: {url}")
                            print(f"   → جزئیات: {message}\n")
                        else:
                            print(f"[✓] ایمن: {url}")
        except FileNotFoundError:
            print("خطا: فایل مورد نظر یافت نشد!")
