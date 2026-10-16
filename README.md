# SBC Password Reset helper

Mobile-first web app that helps South Bank Colleges students create a valid college password.
Students pick a language (16 available), enter their student ID, and the password is checked live
against the college rules. They then get an "account details" card to screenshot.

Client-only: nothing is stored or sent anywhere. All state lives in memory and is cleared by Reset.

## Run
No build step or dependencies. Open `index.html` in a browser, or serve the folder:

    python3 -m http.server 8000

## Files
- `index.html` – page shell
- `styles.css` – styles
- `app.js` – screens, validation, password suggestion, copy buttons
- `i18n.js` – all copy for the 16 languages (translations need native-speaker review for Somali, Luganda, Amharic, Kurdish)

Configurable constants (`COLLEGE`, `EMAIL_DOMAIN`) are at the top of `app.js`.
