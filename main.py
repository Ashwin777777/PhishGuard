import os
from url_analyzer import analyze_url
from email_analyzer import analyze_email_content

def display_results(analysis_output):
    """Prints the analysis results in a formatted way."""
    print("\n" + "="*50)
    print(f"PHISHING ANALYSIS REPORT")
    print("="*50)

    if 'url' in analysis_output:
        print(f"Analyzed Type: URL")
        print(f"URL: {analysis_output['url']}")
    elif 'email_body_snippet' in analysis_output:
        print(f"Analyzed Type: Email Content")
        print(f"Email Snippet: {analysis_output['email_body_snippet']}")

    print(f"Phishing Score: {analysis_output['phishing_score']}")
    print(f"Risk Level: {analysis_output['risk_level']}")

    print("\nIndicators Found:")
    if analysis_output['indicators']:
        for indicator in analysis_output['indicators']:
            print(f"- {indicator}")
    else:
        print("- No specific indicators found.")

    if 'extracted_links_analysis' in analysis_output and analysis_output['extracted_links_analysis']:
        print("\n--- Embedded Link Analysis ---")
        for i, link_analysis in enumerate(analysis_output['extracted_links_analysis']):
            print(f"\nLink {i+1}: {link_analysis['url']}")
            print(f"  Link Phishing Score: {link_analysis['phishing_score']}")
            print(f"  Link Risk Level: {link_analysis['risk_level']}")
            if link_analysis['indicators']:
                for indicator in link_analysis['indicators']:
                    print(f"    - {indicator}")
            else:
                print("    - No specific indicators for this link.")
    print("="*50 + "\n")

def main():
    """Main function to run the PhishGuard analyzer."""
    print("Welcome to PhishGuard - Your Phishing Analyzer!")
    print("This tool helps detect potential phishing attempts.")

    # Ensure data directory and files exist for demonstration
    if not os.path.exists('data'):
        os.makedirs('data')
    if not os.path.exists('data/legitimate_domains.txt'):
        with open('data/legitimate_domains.txt', 'w') as f:
            f.write("google.com\n")
            f.write("microsoft.com\n")
            f.write("paypal.com\n")
            f.write("amazon.com\n")
            f.write("facebook.com\n")
            f.write("apple.com\n")
            f.write("netflix.com\n")
            f.write("twitter.com\n")
            f.write("linkedin.com\n")
            f.write("wikipedia.org\n")
    if not os.path.exists('data/suspicious_keywords.txt'):
        with open('data/suspicious_keywords.txt', 'w') as f:
            f.write("urgent\n")
            f.write("verify\n")
            f.write("account\n")
            f.write("password\n")
            f.write("security alert\n")
            f.write("invoice\n")
            f.write("click here\n")
            f.write("suspension\n")
            f.write("update information\n")
            f.write("bank details\n")
            f.write("credit card\n")
            f.write("winnings\n")
            f.write("prize\n")
            f.write("limited time offer\n")
            f.write("action required\n")


    while True:
        print("\nChoose an analysis type:")
        print("1. Analyze URL")
        print("2. Analyze Email Content")
        print("3. Exit")

        choice = input("Enter your choice (1/2/3): ").strip()

        if choice == '1':
            url_input = input("Enter the URL to analyze: ").strip()
            if url_input:
                results = analyze_url(url_input)
                display_results(results)
            else:
                print("URL cannot be empty.")
        elif choice == '2':
            print("Paste the email content. Type 'EOF' on a new line and press Enter when done.")
            email_lines = []
            while True:
                line = input()
                if line.strip().upper() == 'EOF':
                    break
                email_lines.append(line)
            email_content = "\n".join(email_lines)

            if email_content:
                results = analyze_email_content(email_content)
                display_results(results)
            else:
                print("Email content cannot be empty.")
        elif choice == '3':
            print("Exiting PhishGuard. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()

