# Google Apps Script — התראות באימייל

מסמך זה מכיל את הקוד המדויק שצריך להוסיף ב-**Google Apps Script** של אביטל
כדי לקבל התראות למייל בכל פעם שיש:

1. **פנייה חדשה** מהאתר (טופס יצירת קשר / מודאל מייל בברושור)
2. **רישום חדש לסדנה** (דרך הברושור `workshop.avital-heal.com`)

> **⚠️ עדכון אבטחה — פעולה נדרשת:** החל מהגרסה הנוכחית, ה-Worker כבר **לא**
> שולח שם/טלפון/אימייל/תוכן פנייה/הערות ל-Apps Script הזה — רק הודעה כללית
> וקישור ל-CRM (כדי לא להעביר מידע אישי דרך שרתי Google). **יש להחליף את
> הקוד ב-Apps Script לגרסה המעודכנת למטה ולפרוס מחדש (Deploy → New version)
> לפני שהשינוי הזה עולה ל-Production** — אחרת המיילים על פניות/הרשמות חדשות
> יפסיקו להגיע (הקוד הישן מצפה לשדות שכבר לא נשלחים).

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
// הערה: הודעה כללית בלבד — ה-Worker כבר לא שולח שם/טלפון/אימייל/תוכן הפנייה
// לשירות חיצוני; יש לפתוח את ה-CRM כדי לראות את הפרטים.
function handleNewContact(data) {
  const { notice, crmLink, timestamp } = data;

  const subject = `🔔 ${notice || 'פנייה חדשה מהאתר'}`;
  const htmlBody = `
    <div dir="rtl" style="font-family: Arial, sans-serif; max-width: 600px;">
      <h2 style="color: #2a5a3e;">📬 ${escapeHtml(notice || 'פנייה חדשה מהאתר')}</h2>
      <p style="color:#555;">תאריך: ${formatDate(timestamp)}</p>
      <p style="margin-top: 20px;"><a href="${escapeHtml(crmLink || 'https://app.avital-heal.com')}" style="background: #9DC8B0; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px;">פתיחת ה-CRM לצפייה בפנייה ➝</a></p>
    </div>
  `;
  GmailApp.sendEmail(NOTIFY_EMAIL, subject, '', { htmlBody, name: 'Avital Heal' });
  return ContentService.createTextOutput(JSON.stringify({ ok: true }))
    .setMimeType(ContentService.MimeType.JSON);
}

// ─── 3. רישום חדש לסדנה ───
// הערה: הודעה כללית בלבד — ראי הערה למעלה.
function handleNewWorkshopRegistration(data) {
  const { notice, crmLink, timestamp } = data;

  const subject = `🎉 ${notice || 'רישום חדש לסדנה'}`;
  const htmlBody = `
    <div dir="rtl" style="font-family: Arial, sans-serif; max-width: 600px;">
      <h2 style="color: #D4AF37;">🌿 ${escapeHtml(notice || 'רישום חדש לסדנה')}</h2>
      <p style="color:#555;">תאריך: ${formatDate(timestamp)}</p>
      <p style="margin-top: 20px;"><a href="${escapeHtml(crmLink || 'https://app.avital-heal.com')}" style="background: #D4AF37; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px;">פתיחת ה-CRM לצפייה ברישום ➝</a></p>
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
נושא: `🔔 התקבלה פנייה חדשה מהאתר`
תוכן: הודעה כללית + תאריך + כפתור לפתיחת ה-CRM לצפייה בפרטים המלאים.

### 🌿 רישום לסדנה
נושא: `🎉 התקבלה הרשמה חדשה לסדנה "..."`
תוכן: הודעה כללית + תאריך + כפתור לפתיחת ה-CRM לצפייה בפרטים המלאים.

---

## טיפים:

- **בדיקה ראשונה:** אחרי ה-deploy, שלחי מייל עצמי דרך המודאל ב-`workshop.avital-heal.com` ועקבי.
- **אם לא מגיע:** היכנסי ל-Apps Script → Executions → תראי אם הייתה ריצה + שגיאה.
- **תיקיית ספאם:** המייל הראשון עלול להגיע לספאם — סמני "לא ספאם" כדי שהבאים יגיעו ל-Inbox.
