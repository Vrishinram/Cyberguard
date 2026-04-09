# CyGuard — Password Strength Analyzer

A premium, enterprise-grade password strength analyzer that evaluates the security of your passwords in real-time and provides actionable recommendations.

## Features

✨ **Core Features**
- 🔍 **Real-time Strength Analysis** — Evaluates password length, complexity, and entropy instantly
- 📊 **Criteria Checklist** — Visual feedback on uppercase, lowercase, numbers, and special characters
- ⏱️ **Crack-Time Estimation** — Estimates how long it would take to crack your password
- 🚨 **Breach Detection** — Checks if your password has been exposed in known data breaches (via Have I Been Pwned API with k-anonymity)
- 💡 **Password Suggestions** — Generates strong, random password alternatives
- 📜 **Password History** — Tracks previously entered passwords using localStorage to help prevent reuse
- 📚 **Educational Content** — Learn section to understand password security best practices

## Technology Stack

- **Frontend**: HTML5, CSS3 (with modern animations and gradients)
- **JavaScript**: Vanilla JavaScript (ES6+) for core logic
- **Security**: Client-side password analysis, k-anonymity for breach checking
- **Fonts**: Inter & JetBrains Mono from Google Fonts

## How It Works

1. **Enter a password** in the analyzer input field
2. **Real-time analysis** evaluates:
   - Password length
   - Character complexity (uppercase, lowercase, numbers, symbols)
   - Shannon entropy
   - Common password detection
   - Keyboard pattern detection
3. **View results**:
   - Strength meter with visual feedback
   - Estimated crack time
   - List of criteria met
   - Breach status
4. **Get suggestions** for stronger passwords
5. **Learn** about password security principles

## File Structure

```
CyGuard/
├── index.html          # Main HTML structure
├── index.css           # Styling and animations
├── app.js              # Core JavaScript logic
└── README.md           # This file
```

## Getting Started

### Prerequisites
- A modern web browser (Chrome, Firefox, Safari, Edge)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/Vrishinram/Cyberguard.git
cd Cyberguard
```

2. Open `index.html` in your browser or serve it locally:
```bash
# Using Python 3
python -m http.server 8000

# Using Python 2
python -m SimpleHTTPServer 8000

# Using Node.js with http-server
npx http-server
```

3. Navigate to `http://localhost:8000` and start analyzing passwords!

## Features in Detail

### Password Strength Meter
- **Very Weak** (Red) — 0-20 points
- **Weak** (Orange) — 21-40 points
- **Fair** (Yellow) — 41-60 points
- **Good** (Light Green) — 61-80 points
- **Strong** (Green) — 81-100 points

### Criteria Evaluation
- Minimum 8 characters
- Contains uppercase letters (A-Z)
- Contains lowercase letters (a-z)
- Contains numbers (0-9)
- Contains special characters (!@#$%^&*)
- Not a common password
- Not a keyboard pattern
- Sufficient entropy (randomness)

### Security Features
- All analysis happens **client-side** — your passwords never leave your device
- Breach checking uses **k-anonymity** to protect privacy (only the first 5 characters of the password hash are sent)
- Password history is stored locally in `localStorage` and never transmitted

## Privacy & Security

Your privacy is paramount:
- **No passwords are transmitted** to any server (breach checking uses k-anonymity)
- **No cookies** are used
- **Local storage only** for password history (which can be cleared anytime)
- Open-source code for transparency

## Contributing

Contributions are welcome! Feel free to submit issues and enhancement requests.

## License

This project is open source and available under the MIT License.

## Author

**Vrishinram** — Cybersecurity Enthusiast

## Disclaimer

CyGuard is a tool for educational and informational purposes. While it provides password strength analysis, always follow your organization's password policies and use a password manager for storing sensitive credentials.

---

**CyGuard** — Your Digital Guardian 🛡️
