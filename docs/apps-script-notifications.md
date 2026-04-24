# Google Apps Script — התראות באימייל

מסמך זה מכיל את הקוד המדויק שצריך להוסיף ב-**Google Apps Script** של אביטל
כדי לקבל התראות למייל בכל פעם שיש:

1. **פנייה חדשה** מהאתר (טופס יצירת קשר / מודאל מייל בברושור)
2. **רישום חדש לסדנה** (דרך הברושור `workshop.avital-heal.com`)

---

## איך לפרוס:

1. היכנסי ל-Google Apps Script: <https://script.google.com>
2. פתחי את הפרויקט הקיים (זה שמטפל בבקשות איפוס סיסמה)
3. החליפי את הפונקציה `doPost(e)` בקוד למטה (או הוסיפי את הבלוקים החדשים)
4. שמרי (Ctrl+S / Cmd+S)
5. **Deploy → Manage deployments** → ליד ה-deployment הנוכחי לחצי על ✏️ → **New version** → **Deploy**

*(לא נדרש לעדכן את ה-URL ב-Worker — הוא נשאר אותו)*

---

## הקוד המלא:

```javascript
// ─── כתובת אימייל לקבלת ההתראות ───
const NOTIFY_EMAIL = 'avital.ho@gmail.com';

function doPost(e) {
  try {
    const data = JSON.parse(e.postData.contents);
    const type = data.type || 'password-reset';  // ברירת מחדל — תאימות לאחור

    if (type === 'password-reset') {
      return handlePasswordReset(data);
    }
    if (type === 'new-contact') {
      return handleNewContact(data);
    }
    if (type === 'new-workshop-registration') {
      return handleNewWorkshopRegistration(data);
    }

    return ContentService.createTextOutput(JSON.stringify({ ok: true, ignored: true }))
      .setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    console.error('doPost error:', err);
    return ContentService.createTextOutput(JSON.stringify({ ok: false, error: String(err) }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}

// ─── 1. איפוס סיסמה (קוד קיים — השאירי כמו שהיה) ───
function handlePasswordReset(data) {
  const { email, name, resetLink } = data;
  GmailApp.sendEmail(
    email,
    'איפוס סיסמה - Avital Heal CRM',
    `שלום ${name || ''},

קיבלנו בקשה לאיפוס הסיסמה שלך ב-Avital Heal CRM.
לחצי על הקישור הבא כדי להגדיר סיסמה חדשה (תוקף שעה):

${resetLink}

אם לא ביקשת איפוס, פשוט התעלמי ממייל זה.`,
    { name: 'Avital Heal' }
  );
  return ContentService.createTextOutput(JSON.stringify({ ok: true }))
    .setMimeType(ContentService.MimeType.JSON);
}

// ─── 2. פנייה חדשה מטופס האתר ───
function handleNewContact(data) {
  const { fullName, phone, email, message, timestamp } = data;

  const subject = `🔔 פנייה חדשה מהאתר - ${fullName}`;
  const htmlBody = `
    <div dir="rtl" style="font-family: Arial, sans-serif; max-width: 600px;">
      <h2 style="color: #2a5a3e;">📬 פנייה חדשה מהאתר</h2>
      <table style="border-collapse: collapse; width: 100%;">
        <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>שם:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${escapeHtml(fullName)}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>טלפון:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${phone ? '<a href="tel:' + escapeHtml(phone) + '">' + escapeHtml(phone) + '</a>' : '—'}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>אימייל:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${email ? '<a href="mailto:' + escapeHtml(email) + '">' + escapeHtml(email) + '</a>' : '—'}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; vertical-align: top;"><strong>הודעה:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd; white-space: pre-wrap;">${escapeHtml(message || '')}</td></tr>
        <tr><td style="padding: 8px;"><strong>תאריך:</strong></td><td style="padding: 8px;">${formatDate(timestamp)}</td></tr>
      </table>
      <p style="margin-top: 20px;"><a href="https://app.avital-heal.com" style="background: #9DC8B0; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px;">פתיחת ה-CRM לצפייה בפנייה ➝</a></p>
    </div>
  `;
  GmailApp.sendEmail(NOTIFY_EMAIL, subject, '', { htmlBody, name: 'Avital Heal' });
  return ContentService.createTextOutput(JSON.stringify({ ok: true }))
    .setMimeType(ContentService.MimeType.JSON);
}

// ─── 3. רישום חדש לסדנה ───
function handleNewWorkshopRegistration(data) {
  const { workshopName, fullName, phone, email, dateLabel, notes, timestamp } = data;

  const subject = `🎉 רישום חדש לסדנה "${workshopName}" - ${fullName}`;
  const htmlBody = `
    <div dir="rtl" style="font-family: Arial, sans-serif; max-width: 600px;">
      <h2 style="color: #D4AF37;">🌿 רישום חדש לסדנה</h2>
      <p style="font-size: 16px; color: #555;"><strong>${escapeHtml(workshopName)}</strong></p>
      <table style="border-collapse: collapse; width: 100%;">
        <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>שם:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${escapeHtml(fullName)}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>טלפון:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;"><a href="tel:${escapeHtml(phone)}">${escapeHtml(phone)}</a></td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>אימייל:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${email ? '<a href="mailto:' + escapeHtml(email) + '">' + escapeHtml(email) + '</a>' : '—'}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>מועד שנבחר:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${escapeHtml(dateLabel || '')}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; vertical-align: top;"><strong>הערות:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd; white-space: pre-wrap;">${escapeHtml(notes || '—')}</td></tr>
        <tr><td style="padding: 8px;"><strong>תאריך:</strong></td><td style="padding: 8px;">${formatDate(timestamp)}</td></tr>
      </table>
      <p style="margin-top: 20px;"><a href="https://app.avital-heal.com" style="background: #D4AF37; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px;">פתיחת ה-CRM לצפייה ברישום ➝</a></p>
    </div>
  `;
  GmailApp.sendEmail(NOTIFY_EMAIL, subject, '', { htmlBody, name: 'Avital Heal' });
  return ContentService.createTextOutput(JSON.stringify({ ok: true }))
    .setMimeType(ContentService.MimeType.JSON);
}

// ─── פונקציות עזר ───
function escapeHtml(s) {
  if (!s) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatDate(iso) {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    return d.toLocaleString('he-IL', { timeZone: 'Asia/Jerusalem' });
  } catch (_) { return iso; }
}
```

---

## מה תקבלי במייל:

### 📬 פנייה חדשה
נושא: `🔔 פנייה חדשה מהאתר - [שם]`
תוכן: טבלה מעוצבת עם שם, טלפון, אימייל, הודעה, תאריך + כפתור לפתיחת ה-CRM.

### 🌿 רישום לסדנה
נושא: `🎉 רישום חדש לסדנה "להיות המרפאה של עצמי" - [שם]`
תוכן: טבלה מעוצבת עם כל הפרטים + המועד שנבחר + כפתור לפתיחת ה-CRM.

---

## טיפים:

- **בדיקה ראשונה:** אחרי ה-deploy, שלחי מייל עצמי דרך המודאל ב-`workshop.avital-heal.com` ועקבי.
- **אם לא מגיע:** היכנסי ל-Apps Script → Executions → תראי אם הייתה ריצה + שגיאה.
- **תיקיית ספאם:** המייל הראשון עלול להגיע לספאם — סמני "לא ספאם" כדי שהבאים יגיעו ל-Inbox.
