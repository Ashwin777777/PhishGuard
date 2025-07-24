import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import os
import re
from urllib.parse import urlparse
import threading

class PhishGuardGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PhishGuard - Phishing Analyzer")
        self.root.geometry("900x800")
        self.root.configure(bg='#f0f0f0')
        
        # Initialize data
        self.setup_data()
        self.create_widgets()
        
        # Show welcome message
        self.show_welcome_message()
    
    def setup_data(self):
        """Initialize legitimate domains and suspicious keywords."""
        self.legitimate_domains = {
            'google.com', 'microsoft.com', 'paypal.com', 'amazon.com',
            'facebook.com', 'apple.com', 'netflix.com', 'twitter.com',
            'linkedin.com', 'wikipedia.org', 'github.com', 'stackoverflow.com',
            'youtube.com', 'instagram.com', 'reddit.com', 'dropbox.com'
        }
        
        self.suspicious_keywords = [
            'urgent', 'verify', 'account', 'password', 'security alert',
            'invoice', 'click here', 'suspension', 'update information',
            'bank details', 'credit card', 'winnings', 'prize',
            'limited time offer', 'action required', 'confirm identity',
            'verify account', 'suspended', 'expire', 'immediate action'
        ]
    
    def create_widgets(self):
        """Create all GUI widgets."""
        # Header
        header_frame = tk.Frame(self.root, bg='#2c3e50', height=100)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(header_frame, text="🛡️ PhishGuard", 
                              font=('Arial', 28, 'bold'), 
                              fg='white', bg='#2c3e50')
        title_label.pack(pady=(15, 5))
        
        subtitle_label = tk.Label(header_frame, text="Advanced Phishing Detection & Analysis Tool", 
                                 font=('Arial', 12), 
                                 fg='#bdc3c7', bg='#2c3e50')
        subtitle_label.pack()
        
        # Main container
        main_container = tk.Frame(self.root, bg='#ecf0f1')
        main_container.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill='both', expand=True)
        
        # Create tabs
        self.create_url_tab()
        self.create_email_tab()
        self.create_results_tab()
    
    def create_url_tab(self):
        """Create the URL analysis tab."""
        self.url_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.url_frame, text="🔍 URL Analysis")
        
        # Main content frame
        content_frame = tk.Frame(self.url_frame, bg='white', relief='solid', bd=1)
        content_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Title
        title = tk.Label(content_frame, text="URL Phishing Analysis", 
                        font=('Arial', 16, 'bold'), bg='white', fg='#2c3e50')
        title.pack(pady=(20, 10))
        
        # Instructions
        instructions = tk.Label(content_frame, 
                               text="Enter a URL below to analyze it for phishing indicators",
                               font=('Arial', 11), bg='white', fg='#7f8c8d')
        instructions.pack(pady=(0, 20))
        
        # URL input frame
        input_frame = tk.Frame(content_frame, bg='white')
        input_frame.pack(fill='x', padx=30, pady=10)
        
        tk.Label(input_frame, text="URL:", font=('Arial', 12, 'bold'), 
                bg='white', fg='#34495e').pack(anchor='w', pady=(0, 5))
        
        self.url_entry = tk.Entry(input_frame, font=('Arial', 11), width=70, relief='solid', bd=1)
        self.url_entry.pack(fill='x', pady=(0, 15), ipady=8)
        
        # Analyze button
        self.url_analyze_btn = tk.Button(input_frame, text="🔍 Analyze URL", 
                                        command=self.analyze_url_clicked,
                                        bg='#3498db', fg='white', 
                                        font=('Arial', 12, 'bold'),
                                        relief='flat', padx=30, pady=10,
                                        cursor='hand2')
        self.url_analyze_btn.pack()
        
        # Example section
        example_frame = tk.LabelFrame(content_frame, text="Example URLs to Test", 
                                     font=('Arial', 11, 'bold'),
                                     bg='#f8f9fa', fg='#495057', relief='solid', bd=1)
        example_frame.pack(fill='x', padx=30, pady=(20, 0))
        
        examples = [
            ("✅ Safe: https://google.com", "#27ae60"),
            ("⚠️ Suspicious: http://g00gle-verify.com", "#f39c12"),
            ("🚨 Dangerous: https://paypal-security.suspicious-site.net", "#e74c3c")
        ]
        
        for example, color in examples:
            example_label = tk.Label(example_frame, text=example, 
                                   font=('Arial', 10), bg='#f8f9fa', fg=color)
            example_label.pack(anchor='w', padx=15, pady=5)
    
    def create_email_tab(self):
        """Create the email analysis tab."""
        self.email_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.email_frame, text="📧 Email Analysis")
        
        # Main content frame
        content_frame = tk.Frame(self.email_frame, bg='white', relief='solid', bd=1)
        content_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Title
        title = tk.Label(content_frame, text="Email Content Analysis", 
                        font=('Arial', 16, 'bold'), bg='white', fg='#2c3e50')
        title.pack(pady=(20, 10))
        
        # Instructions
        instructions = tk.Label(content_frame, 
                               text="Paste email content below to analyze for phishing indicators",
                               font=('Arial', 11), bg='white', fg='#7f8c8d')
        instructions.pack(pady=(0, 20))
        
        # Email input frame
        input_frame = tk.Frame(content_frame, bg='white')
        input_frame.pack(fill='both', expand=True, padx=30, pady=10)
        
        tk.Label(input_frame, text="Email Content:", font=('Arial', 12, 'bold'), 
                bg='white', fg='#34495e').pack(anchor='w', pady=(0, 5))
        
        # Text area with scrollbar
        text_frame = tk.Frame(input_frame, bg='white')
        text_frame.pack(fill='both', expand=True, pady=(0, 15))
        
        self.email_text = scrolledtext.ScrolledText(text_frame, height=15, 
                                                   font=('Consolas', 10), 
                                                   relief='solid', bd=1,
                                                   wrap='word')
        self.email_text.pack(fill='both', expand=True)
        
        # Button frame
        btn_frame = tk.Frame(input_frame, bg='white')
        btn_frame.pack(fill='x', pady=(10, 0))
        
        self.email_analyze_btn = tk.Button(btn_frame, text="🔍 Analyze Email", 
                                          command=self.analyze_email_clicked,
                                          bg='#e74c3c', fg='white', 
                                          font=('Arial', 12, 'bold'),
                                          relief='flat', padx=30, pady=10,
                                          cursor='hand2')
        self.email_analyze_btn.pack(side='left')
        
        clear_btn = tk.Button(btn_frame, text="🗑️ Clear", 
                             command=self.clear_email,
                             bg='#95a5a6', fg='white', 
                             font=('Arial', 12, 'bold'),
                             relief='flat', padx=20, pady=10,
                             cursor='hand2')
        clear_btn.pack(side='right')
    
    def create_results_tab(self):
        """Create the results display tab."""
        self.results_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.results_frame, text="📊 Results")
        
        # Results display frame
        display_frame = tk.Frame(self.results_frame, bg='#2c3e50', relief='solid', bd=2)
        display_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Results header
        header = tk.Label(display_frame, text="📊 Analysis Results", 
                         font=('Arial', 16, 'bold'), 
                         fg='white', bg='#2c3e50')
        header.pack(pady=(20, 10))
        
        # Results text area
        self.results_text = scrolledtext.ScrolledText(display_frame, 
                                                     font=('Consolas', 11), 
                                                     bg='#34495e', fg='#ecf0f1',
                                                     relief='flat', bd=0,
                                                     insertbackground='white')
        self.results_text.pack(fill='both', expand=True, padx=20, pady=(0, 20))
    
    def show_welcome_message(self):
        """Display welcome message in results."""
        welcome_msg = """
🛡️ Welcome to PhishGuard - Advanced Phishing Detection Tool! 🛡️

═══════════════════════════════════════════════════════════════

📋 HOW TO USE:
   1. Select either 'URL Analysis' or 'Email Analysis' tab
   2. Enter the content you want to analyze
   3. Click the analyze button
   4. View detailed results here

🎯 WHAT WE DETECT:
   • Suspicious domain patterns
   • Homograph attacks (look-alike characters)
   • Insecure protocols (HTTP vs HTTPS)
   • Phishing keywords and urgency tactics
   • Suspicious links in emails
   • Personal information requests

📊 RISK LEVELS:
   ✅ LOW (0-25):      Appears safe
   ⚠️ MEDIUM (26-50):  Some suspicious indicators
   🚨 HIGH (51-75):    Likely phishing attempt
   💀 CRITICAL (76+):  Definite phishing attempt

═══════════════════════════════════════════════════════════════

Ready to analyze! Select a tab above to get started... 🚀
        """
        self.results_text.insert(tk.END, welcome_msg)
    
    def analyze_url_clicked(self):
        """Handle URL analyze button click."""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Required", "Please enter a URL to analyze.")
            return
        
        # Switch to results tab
        self.notebook.select(self.results_frame)
        
        # Disable button and show progress
        self.url_analyze_btn.config(state='disabled', text='Analyzing...')
        
        # Run analysis in thread
        threading.Thread(target=self.analyze_url, args=(url,), daemon=True).start()
    
    def analyze_email_clicked(self):
        """Handle email analyze button click."""
        email_content = self.email_text.get(1.0, tk.END).strip()
        if not email_content:
            messagebox.showwarning("Input Required", "Please enter email content to analyze.")
            return
        
        # Switch to results tab
        self.notebook.select(self.results_frame)
        
        # Disable button and show progress
        self.email_analyze_btn.config(state='disabled', text='Analyzing...')
        
        # Run analysis in thread
        threading.Thread(target=self.analyze_email, args=(email_content,), daemon=True).start()
    
    def clear_email(self):
        """Clear email text area."""
        self.email_text.delete(1.0, tk.END)
    
    def analyze_url(self, url):
        """Analyze URL for phishing indicators."""
        try:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Parse URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            indicators = []
            phishing_score = 0
            
            # Domain analysis
            if domain in self.legitimate_domains:
                indicators.append("✅ Domain found in legitimate domains list")
                phishing_score -= 20
            else:
                # Check for suspicious patterns in domain
                suspicious_patterns = [
                    ('-', "Contains hyphens (often used in phishing)"),
                    ('_', "Contains underscores (uncommon in legitimate domains)"),
                    ('0', "Contains digit '0' (possible homograph attack)"),
                    ('1', "Contains digit '1' (possible homograph attack)")
                ]
                
                for pattern, description in suspicious_patterns:
                    if pattern in domain:
                        indicators.append(f"⚠️ {description}")
                        phishing_score += 15
                
                # Check for brand impersonation
                for legit_domain in self.legitimate_domains:
                    if legit_domain.replace('.', '') in domain and domain != legit_domain:
                        indicators.append(f"🚨 Possible impersonation of {legit_domain}")
                        phishing_score += 40
                        break
            
            # Protocol check
            if parsed_url.scheme == 'http':
                indicators.append("🚨 Using insecure HTTP protocol")
                phishing_score += 30
            else:
                indicators.append("✅ Using secure HTTPS protocol")
            
            # URL length check
            if len(url) > 100:
                indicators.append("⚠️ Very long URL (suspicious)")
                phishing_score += 20
            
            # Suspicious TLD check
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top']
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    indicators.append(f"🚨 Suspicious top-level domain: {tld}")
                    phishing_score += 35
                    break
            
            # URL shortener check
            shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link']
            for shortener in shorteners:
                if shortener in domain:
                    indicators.append(f"⚠️ URL shortener detected: {shortener}")
                    phishing_score += 15
                    break
            
            # Subdomain analysis
            subdomains = domain.count('.')
            if subdomains > 2:
                indicators.append(f"⚠️ Multiple subdomains detected ({subdomains})")
                phishing_score += 10
            
            # Final score adjustment
            phishing_score = max(0, min(100, phishing_score))
            
            # Determine risk level
            if phishing_score <= 25:
                risk_level = "LOW"
                risk_emoji = "✅"
                risk_color = "#27ae60"
            elif phishing_score <= 50:
                risk_level = "MEDIUM"
                risk_emoji = "⚠️"
                risk_color = "#f39c12"
            elif phishing_score <= 75:
                risk_level = "HIGH"
                risk_emoji = "🚨"
                risk_color = "#e67e22"
            else:
                risk_level = "CRITICAL"
                risk_emoji = "💀"
                risk_color = "#c0392b"
            
            # Create results
            results = {
                'type': 'URL',
                'url': url,
                'phishing_score': phishing_score,
                'risk_level': risk_level,
                'risk_emoji': risk_emoji,
                'indicators': indicators
            }
            
            # Update UI in main thread
            self.root.after(0, lambda: self.display_results(results))
            
        except Exception as e:
            error_results = {
                'type': 'URL',
                'url': url,
                'phishing_score': 50,
                'risk_level': 'ERROR',
                'risk_emoji': '❌',
                'indicators': [f"❌ Error analyzing URL: {str(e)}"]
            }
            self.root.after(0, lambda: self.display_results(error_results))
        
        finally:
            # Re-enable button
            self.root.after(0, lambda: self.url_analyze_btn.config(state='normal', text='🔍 Analyze URL'))
    
    def analyze_email(self, email_content):
        """Analyze email content for phishing indicators."""
        try:
            indicators = []
            phishing_score = 0
            email_lower = email_content.lower()
            
            # Keyword analysis
            found_keywords = []
            for keyword in self.suspicious_keywords:
                if keyword in email_lower:
                    found_keywords.append(keyword)
                    phishing_score += 8
            
            if found_keywords:
                indicators.append(f"🚨 Suspicious keywords: {', '.join(found_keywords[:5])}")
            
            # Urgency detection
            urgency_phrases = [
                'urgent', 'immediate', 'expire', 'suspend', 'deadline',
                'act now', 'limited time', 'expires today', 'final notice'
            ]
            found_urgency = [phrase for phrase in urgency_phrases if phrase in email_lower]
            if found_urgency:
                indicators.append(f"⚠️ Urgency tactics: {', '.join(found_urgency[:3])}")
                phishing_score += 20
            
            # Personal information requests
            personal_info = [
                'password', 'ssn', 'social security', 'credit card', 
                'bank account', 'pin', 'cvv', 'routing number'
            ]
            found_personal = [info for info in personal_info if info in email_lower]
            if found_personal:
                indicators.append(f"🚨 Requests personal info: {', '.join(found_personal[:3])}")
                phishing_score += 30
            
            # Link analysis
            url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            urls = re.findall(url_pattern, email_content)
            
            if urls:
                indicators.append(f"🔗 Contains {len(urls)} link(s)")
                if len(urls) > 3:
                    indicators.append("⚠️ High number of links (suspicious)")
                    phishing_score += 15
                
                # Analyze first few links
                suspicious_links = 0
                for url in urls[:3]:  # Check first 3 links
                    if not any(domain in url.lower() for domain in self.legitimate_domains):
                        suspicious_links += 1
                
                if suspicious_links > 0:
                    indicators.append(f"🚨 {suspicious_links} suspicious link(s) detected")
                    phishing_score += suspicious_links * 15
            
            # Grammar and formatting check
            grammar_issues = 0
            if email_content.count('  ') > 5:  # Multiple spaces
                grammar_issues += 1
            if email_content.count('!!') > 2:  # Multiple exclamations
                grammar_issues += 1
            if len(re.findall(r'[A-Z]{3,}', email_content)) > 3:  # Too much caps
                grammar_issues += 1
            
            if grammar_issues > 0:
                indicators.append(f"⚠️ Poor formatting/grammar ({grammar_issues} issues)")
                phishing_score += grammar_issues * 10
            
            # Attachment mentions
            attachment_words = ['attachment', 'download', 'install', 'executable', 'zip', 'pdf']
            if any(word in email_lower for word in attachment_words):
                indicators.append("⚠️ Mentions attachments/downloads")
                phishing_score += 15
            
            # Sender impersonation check
            impersonation_words = ['bank', 'paypal', 'amazon', 'microsoft', 'apple', 'google']
            found_impersonation = [word for word in impersonation_words if word in email_lower]
            if found_impersonation:
                indicators.append(f"⚠️ Claims to be from: {', '.join(found_impersonation[:3])}")
                phishing_score += 20
            
            # Final score
            phishing_score = max(0, min(100, phishing_score))
            
            # Determine risk level
            if phishing_score <= 25:
                risk_level = "LOW"
                risk_emoji = "✅"
            elif phishing_score <= 50:
                risk_level = "MEDIUM"
                risk_emoji = "⚠️"
            elif phishing_score <= 75:
                risk_level = "HIGH"
                risk_emoji = "🚨"
            else:
                risk_level = "CRITICAL"
                risk_emoji = "💀"
            
            # Create results
            results = {
                'type': 'EMAIL',
                'email_snippet': email_content[:150] + "..." if len(email_content) > 150 else email_content,
                'phishing_score': phishing_score,
                'risk_level': risk_level,
                'risk_emoji': risk_emoji,
                'indicators': indicators,
                'urls_found': urls[:5] if urls else []  # First 5 URLs
            }
            
            # Update UI in main thread
            self.root.after(0, lambda: self.display_results(results))
            
        except Exception as e:
            error_results = {
                'type': 'EMAIL',
                'email_snippet': email_content[:100] + "..." if len(email_content) > 100 else email_content,
                'phishing_score': 50,
                'risk_level': 'ERROR',
                'risk_emoji': '❌',
                'indicators': [f"❌ Error analyzing email: {str(e)}"]
            }
            self.root.after(0, lambda: self.display_results(error_results))
        
        finally:
            # Re-enable button
            self.root.after(0, lambda: self.email_analyze_btn.config(state='normal', text='🔍 Analyze Email'))
    
    def display_results(self, results):
        """Display analysis results."""
        # Clear previous results
        self.results_text.delete(1.0, tk.END)
        
        # Format results
        output = f"""
╔════════════════════════════════════════════════════════════════╗
║                    🛡️ PHISHING ANALYSIS REPORT                 ║
╠════════════════════════════════════════════════════════════════╣

📊 ANALYSIS TYPE: {results['type']}
"""
        
        if results['type'] == 'URL':
            output += f"🔗 URL: {results['url']}\n"
        else:
            output += f"📧 EMAIL CONTENT: {results['email_snippet']}\n"
        
        output += f"""
╔═══ RISK ASSESSMENT ═══╗
║ Score: {results['phishing_score']:3d}/100              ║
║ Level: {results['risk_emoji']} {results['risk_level']:<15} ║
╚════════════════════════╝

🔍 INDICATORS FOUND:
"""
        
        if results['indicators']:
            for i, indicator in enumerate(results['indicators'], 1):
                output += f"{i:2d}. {indicator}\n"
        else:
            output += "   ✅ No suspicious indicators detected\n"
        
        # Add URLs if email analysis
        if results['type'] == 'EMAIL' and results.get('urls_found'):
            output += f"\n🔗 LINKS DETECTED ({len(results['urls_found'])}):\n"
            for i, url in enumerate(results['urls_found'], 1):
                output += f"{i:2d}. {url}\n"
        
        # Risk interpretation
        output += f"""
╔═══ RECOMMENDATION ═══╗
"""
        
        if results['phishing_score'] <= 25:
            output += "║ ✅ SAFE: Low risk detected                               ║\n"
            output += "║    This appears to be legitimate                         ║\n"
        elif results['phishing_score'] <= 50:
            output += "║ ⚠️ CAUTION: Some suspicious indicators                  ║\n"
            output += "║    Verify source before taking action                    ║\n"
        elif results['phishing_score'] <= 75:
            output += "║ 🚨 DANGER: High probability of phishing                ║\n"
            output += "║    Do not click links or provide information            ║\n"
        else:
            output += "║ 💀 CRITICAL: Almost certainly a phishing attempt       ║\n"
            output += "║    Block sender and report as phishing                  ║\n"
        
        output += "╚══════════════════════════════════════════════════════════╝\n"
        output += f"\n🕐 Analysis completed at: {tk.datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        output += "═" * 68 + "\n"
        
        # Insert results
        self.results_text.insert(tk.END, output)
        self.results_text.see(tk.END)

def main():
    """Main function to run the application."""
    root = tk.Tk()
    
    # Fix for datetime import
    import datetime
    tk.datetime = datetime
    
    app = PhishGuardGUI(root)
    
    try:
        root.mainloop()
    except Exception as e:
        messagebox.showerror("Error", f"Application error: {str(e)}")

if __name__ == "__main__":
    main()
