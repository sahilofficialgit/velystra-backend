// server.js
const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const cron = require('node-cron');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Google Sheets Setup
const auth = new google.auth.GoogleAuth({
  keyFile: 'credentials.json',
  scopes: ['https://www.googleapis.com/auth/spreadsheets'],
});

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// ==========================================
// BREVO HTTPS REST API HELPER (100% BYPASSES SMTP BLOCKS)
// ==========================================
async function sendBrevoEmail(toEmail, toName, subject, htmlContent) {
  try {
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'api-key': process.env.BREVO_API_KEY,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        sender: {
          name: 'Velystra Technology',
          email: process.env.EMAIL_USER,
        },
        to: [{ email: toEmail, name: toName || toEmail }],
        subject: subject,
        htmlContent: htmlContent,
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      console.error('Brevo API Failed:', data);
    } else {
      console.log('Email sent successfully via Brevo API to:', toEmail);
    }
  } catch (error) {
    console.error('Brevo API Request Error:', error);
  }
}

const formatStr = (dateObj) => {
  const dd = String(dateObj.getDate()).padStart(2, '0');
  const mm = String(dateObj.getMonth() + 1).padStart(2, '0');
  const yyyy = dateObj.getFullYear();
  return `${dd}/${mm}/${yyyy}`;
};

// ==========================================
// 1. STATUS CHECK API
// ==========================================
app.get('/api/check-status/:regId', async (req, res) => {
  try {
    const regIdToCheck = req.params.regId.replace(/-/g, '').toUpperCase();
    const spreadsheetId = process.env.SPREADSHEET_ID;

    const client = await auth.getClient();
    const sheets = google.sheets({ version: 'v4', auth: client });

    const response = await sheets.spreadsheets.values.get({
      spreadsheetId,
      range: 'Form Responses 1!A:L',
    });

    const rows = response.data.values;
    if (!rows || rows.length === 0) return res.status(404).json({ success: false, message: 'No data found' });

    let userFound = false;
    let isCompleted = false;
    let userData = {};

    for (let i = 1; i < rows.length; i++) {
      const row = rows[i];
      if (row[5] && row[5].replace(/-/g, '').toUpperCase() === regIdToCheck) {
        userFound = true;
        const taskStatus = row[6] ? row[6].toString().trim().toLowerCase() : '';
        if (taskStatus === 'done') isCompleted = true;

        const rawCertId = row[10] ? row[10].toString().trim() : '';
        const validCertId = rawCertId.startsWith('VTCC') ? rawCertId : '';

        userData = {
          name: row[1],
          email: row[2],
          domain: row[4],
          status: taskStatus,
          duration: row[7] || '1 Month',
          startDate: row[8] || '',
          endDate: row[9] || '',
          certId: validCertId,
          issueDate: row[11] || '',
        };
        break;
      }
    }

    if (!userFound) return res.status(404).json({ success: false, message: 'Registration ID not found.' });
    return res.json({ success: true, isCompleted, message: isCompleted ? 'Internship Completed!' : 'Tasks Pending', user: userData });
  } catch (error) {
    console.error('Check Status Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ==========================================
// 2. SECURE CREATE ORDER API
// ==========================================
app.post('/api/create-order', async (req, res) => {
  try {
    const { regId, deliveryOption } = req.body;
    const cleanRegId = regId.replace(/-/g, '').toUpperCase();

    const spreadsheetId = process.env.SPREADSHEET_ID;
    const client = await auth.getClient();
    const sheets = google.sheets({ version: 'v4', auth: client });
    const response = await sheets.spreadsheets.values.get({ spreadsheetId, range: 'Form Responses 1!A:J' });
    const rows = response.data.values;

    let userDuration = '1 Month';
    let userFound = false;

    for (let i = 1; i < rows.length; i++) {
      if (rows[i][5] && rows[i][5].replace(/-/g, '').toUpperCase() === cleanRegId) {
        userDuration = rows[i][7] || '1 Month';
        userFound = true;
        break;
      }
    }

    if (!userFound) return res.status(404).json({ success: false, message: 'User not found' });

    let finalAmount = 150;
    if (userDuration.includes('3')) {
      finalAmount = deliveryOption === 'printed' ? 450 : 300;
    } else if (userDuration.includes('6')) {
      finalAmount = deliveryOption === 'printed' ? 700 : 500;
    } else {
      finalAmount = deliveryOption === 'printed' ? 299 : 150;
    }

    const options = {
      amount: finalAmount * 100,
      currency: 'INR',
      receipt: `receipt_${cleanRegId}`,
    };
    const order = await razorpay.orders.create(options);
    if (!order) return res.status(500).json({ success: false, message: 'Order creation failed' });

    res.json({ success: true, order });
  } catch (error) {
    console.error('Secure Order Creation Error:', error);
    res.status(500).json({ success: false, message: 'Server error during payment creation' });
  }
});

// ==========================================
// 3. PAYMENT VERIFY API (WITH ADMIN EMAIL VIA BREVO API)
// ==========================================
app.post('/api/verify-payment', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, regId, deliveryOption, address } = req.body;
    const cleanRegId = regId.replace(/-/g, '').toUpperCase();

    const body = razorpay_order_id + '|' + razorpay_payment_id;
    const expectedSignature = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(body.toString()).digest('hex');

    if (expectedSignature === razorpay_signature) {
      const spreadsheetId = process.env.SPREADSHEET_ID;
      const client = await auth.getClient();
      const sheets = google.sheets({ version: 'v4', auth: client });

      const response = await sheets.spreadsheets.values.get({ spreadsheetId, range: 'Form Responses 1!A:L' });
      const rows = response.data.values;
      let rowIndex = -1;
      let existingCertId = '';

      for (let i = 1; i < rows.length; i++) {
        if (rows[i][5] && rows[i][5].replace(/-/g, '').toUpperCase() === cleanRegId) {
          rowIndex = i + 1;
          existingCertId = rows[i][10] || '';
          break;
        }
      }

      if (rowIndex !== -1) {
        if (existingCertId && existingCertId.trim() !== '') {
          return res.json({ success: true, message: 'Existing ID used.', certId: existingCertId, issueDate: rows[rowIndex - 1][11] });
        }

        const year = new Date().getFullYear().toString().slice(-2);
        const random6Digits = Math.floor(100000 + Math.random() * 900000);
        const newCertId = `VTCC${year}${random6Digits}`;

        const internshipEndDate = rows[rowIndex - 1][9];
        const issueDate = internshipEndDate ? internshipEndDate : new Date().toLocaleDateString('en-GB');

        await sheets.spreadsheets.values.update({
          spreadsheetId,
          range: `Form Responses 1!K${rowIndex}:L${rowIndex}`,
          valueInputOption: 'USER_ENTERED',
          requestBody: { values: [[newCertId, issueDate]] },
        });

        // 📦 AGAR PRINTED HAI TOH ADMIN KO NOTIFICATION
        if (deliveryOption === 'printed') {
          const studentName = rows[rowIndex - 1][1];
          const studentEmail = rows[rowIndex - 1][2];
          const studentPhone = rows[rowIndex - 1][3];
          const studentDomain = rows[rowIndex - 1][4];

          const adminHtml = `
            <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
              <h2 style="color: #2563EB;">New Printed Certificate Order! 🚀</h2>
              <p>A student has successfully paid for a <strong>Printed + Courier</strong> certificate.</p>
              <div style="background: #f8fafc; padding: 15px; border-radius: 8px; border-left: 4px solid #2563EB; margin: 20px 0;">
                <p><strong>Name:</strong> ${studentName}</p>
                <p><strong>Email:</strong> ${studentEmail}</p>
                <p><strong>Phone (WhatsApp):</strong> ${studentPhone}</p>
                <p><strong>Registration ID:</strong> ${cleanRegId}</p>
                <p><strong>Domain:</strong> ${studentDomain}</p>
                <p><strong>Delivery Address:</strong><br><span style="color: #1e40af; font-size: 16px;">${address || 'Address not provided'}</span></p>
              </div>
              <p>Please dispatch the printed certificate to the above address.</p>
            </div>
          `;

          sendBrevoEmail(
            'velystratechnology@gmail.com',
            'Velystra Admin',
            `📦 NEW PRINTED CERTIFICATE ORDER: ${cleanRegId}`,
            adminHtml
          );
        }

        res.json({ success: true, message: 'Payment verified!', certId: newCertId, issueDate });
      } else {
        res.json({ success: false, message: 'User not found.' });
      }
    } else {
      res.status(400).json({ success: false, message: 'Invalid Signature.' });
    }
  } catch (error) {
    console.error('Payment Verify Error:', error);
    res.status(500).json({ success: false, message: 'Verification Error' });
  }
});

// ==========================================
// 4. APPLICATION FORM API (OFFER LETTER EMAIL VIA BREVO API)
// ==========================================
app.post('/api/apply', async (req, res) => {
  try {
    const { name, email, whatsapp, domain, duration } = req.body;

    let prefix = 'VTXX';
    if (domain === 'Frontend Development') prefix = 'VTFE';
    else if (domain === 'Backend Development') prefix = 'VTBE';
    else if (domain === 'Full Stack Development') prefix = 'VTFS';

    const currentYearStr = new Date().getFullYear().toString().slice(-2);
    const random6Digits = Math.floor(100000 + Math.random() * 900000);
    const regId = `${prefix}${currentYearStr}${random6Digits}`;

    const today = new Date();
    const nextMonthFirst = new Date(today.getFullYear(), today.getMonth() + 1, 1);
    const durationMonths = parseInt(duration.split(' ')[0]) || 1;
    const targetEndDate = new Date(today.getFullYear(), today.getMonth() + 1 + durationMonths, 0);

    const startDate = formatStr(nextMonthFirst);
    const endDate = formatStr(targetEndDate);
    const timestamp = new Date().toLocaleString('en-GB');

    const spreadsheetId = process.env.SPREADSHEET_ID;
    const client = await auth.getClient();
    const sheets = google.sheets({ version: 'v4', auth: client });

    await sheets.spreadsheets.values.append({
      spreadsheetId,
      range: 'Form Responses 1!A:A',
      valueInputOption: 'USER_ENTERED',
      insertDataOption: 'INSERT_ROWS',
      requestBody: { values: [[timestamp, name, email, whatsapp, domain, regId, 'Pending', duration, startDate, endDate]] },
    });

    // 📩 SENDING WELCOME & OFFER LETTER LINK VIA BREVO API
    const userEmailHtml = `
      <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
        <h2 style="color: #0A192F;">Congratulations, ${name}! 🎉</h2>
        <p>Your application for the <strong>${domain}</strong> internship has been successfully accepted.</p>
        <div style="background: #f8fafc; padding: 15px; border-radius: 8px; border-left: 4px solid #0A192F; margin: 20px 0;">
          <p><strong>Registration ID:</strong> <span style="font-size: 18px; color: #0A192F; font-family: monospace;">${regId}</span></p>
          <p><strong>Duration:</strong> ${duration}</p>
          <p><strong>Start Date:</strong> ${startDate}</p>
          <p><strong>End Date:</strong> ${endDate}</p>
        </div>
        <p>You can download your official internship offer letter directly from our portal using your Registration ID:</p>
        <div style="margin: 25px 0;">
          <a href="https://your-website.com/offer-letter?regId=${regId}" 
             style="background: #0A192F; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
             📥 Download Offer Letter
          </a>
        </div>
        <p>Please keep your Registration ID secure for all task submissions and final certification.</p>
        <p>Best Regards,<br><strong>Team Velystra Technology</strong></p>
      </div>
    `;

    sendBrevoEmail(
      email,
      name,
      'Welcome & Official Internship Offer Letter - Velystra Technology',
      userEmailHtml
    );

    res.json({ success: true, message: 'Application Submitted!', data: { regId, startDate, endDate, duration } });
  } catch (error) {
    console.error('Apply API Error:', error);
    res.status(500).json({ success: false, message: 'Server Error' });
  }
});

// ==========================================
// 5. DAILY CRON JOB (EMAILS VIA BREVO API)
// ==========================================
cron.schedule('0 8 * * *', async () => {
  console.log('Running Daily Email Automation Check...');
  try {
    const client = await auth.getClient();
    const sheets = google.sheets({ version: 'v4', auth: client });
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: process.env.SPREADSHEET_ID,
      range: 'Form Responses 1!A:N',
    });

    const rows = response.data.values;
    if (!rows || rows.length === 0) return;

    const todayObj = new Date();
    const todayStr = formatStr(todayObj);

    const threeDaysLaterObj = new Date(todayObj);
    threeDaysLaterObj.setDate(todayObj.getDate() + 3);
    const reminderDateStr = formatStr(threeDaysLaterObj);

    for (let i = 1; i < rows.length; i++) {
      const name = rows[i][1];
      const email = rows[i][2];
      const regId = rows[i][5];
      const startDate = rows[i][8];
      const endDate = rows[i][9];

      // Condition 1: Internship Starts Today
      if (startDate === todayStr) {
        sendBrevoEmail(
          email,
          name,
          '🚀 Your Velystra Internship Starts Today!',
          `<p>Hi ${name},</p><p>Welcome aboard! Your internship officially begins today. Keep an eye on your dashboard/tasks.</p>`
        );
      }

      // Condition 2: 3 Days Left Reminder
      if (endDate === reminderDateStr) {
        sendBrevoEmail(
          email,
          name,
          '⏳ Reminder: 3 Days Left for Submission!',
          `<p>Hi ${name},</p><p>Your internship end date is approaching on <strong>${endDate}</strong>. Please ensure all tasks are submitted to be eligible for your certificate.</p>`
        );
      }

      // Condition 3: Status 'Done' - Send Certificate Unlock Email
      const status = rows[i][6] ? rows[i][6].toString().trim().toLowerCase() : '';
      const emailSentFlag = rows[i][13] ? rows[i][13].toString().trim() : '';

      if (status === 'done' && emailSentFlag !== 'Sent') {
        const certHtml = `
          <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
            <h2 style="color: #16A34A;">Congratulations, ${name}! 🎉</h2>
            <p>Great news! Your internship tasks at <strong>Velystra Technology</strong> have been reviewed and marked as <strong>Completed</strong>.</p>
            <p>You can now visit our website, enter your Registration ID (<strong>${regId}</strong>), and unlock/download your official certificate.</p>
            <p>Best Regards,<br><strong>Team Velystra Technology</strong></p>
          </div>
        `;

        sendBrevoEmail(
          email,
          name,
          '🎓 Congratulations! Your Internship Certificate is Ready',
          certHtml
        );

        await sheets.spreadsheets.values.update({
          spreadsheetId: process.env.SPREADSHEET_ID,
          range: `Form Responses 1!N${i + 1}`,
          valueInputOption: 'USER_ENTERED',
          requestBody: { values: [['Sent']] },
        });
      }
    }
  } catch (error) {
    console.error('Cron Job Error:', error);
  }
});

// ==========================================
// 6. TASK SUBMISSION API
// ==========================================
app.post('/api/submit-task', async (req, res) => {
  try {
    const { regId, taskLink } = req.body;
    const cleanRegId = regId.replace(/-/g, '').toUpperCase();

    const spreadsheetId = process.env.SPREADSHEET_ID;
    const client = await auth.getClient();
    const sheets = google.sheets({ version: 'v4', auth: client });

    const response = await sheets.spreadsheets.values.get({
      spreadsheetId,
      range: 'Form Responses 1!A:M',
    });

    const rows = response.data.values;
    if (!rows || rows.length === 0) return res.status(404).json({ success: false, message: 'Database empty' });

    let rowIndex = -1;
    for (let i = 1; i < rows.length; i++) {
      if (rows[i][5] && rows[i][5].replace(/-/g, '').toUpperCase() === cleanRegId) {
        rowIndex = i + 1;
        break;
      }
    }

    if (rowIndex !== -1) {
      await sheets.spreadsheets.values.update({
        spreadsheetId,
        range: `Form Responses 1!G${rowIndex}`,
        valueInputOption: 'USER_ENTERED',
        requestBody: { values: [['Review Pending']] },
      });

      await sheets.spreadsheets.values.update({
        spreadsheetId,
        range: `Form Responses 1!M${rowIndex}`,
        valueInputOption: 'USER_ENTERED',
        requestBody: { values: [[taskLink]] },
      });

      res.json({ success: true, message: 'Task submitted successfully! Our team will review it soon.' });
    } else {
      res.status(404).json({ success: false, message: 'Registration ID not found. Please check and try again.' });
    }
  } catch (error) {
    console.error('Task Submit Error:', error);
    res.status(500).json({ success: false, message: 'Server error during submission.' });
  }
});

// ==========================================
// 7. CERTIFICATE VALIDATION API
// ==========================================
app.get('/api/validate/:certId', async (req, res) => {
  try {
    const certIdToCheck = req.params.certId.replace(/-/g, '').toUpperCase();
    const spreadsheetId = process.env.SPREADSHEET_ID;

    const client = await auth.getClient();
    const sheets = google.sheets({ version: 'v4', auth: client });

    const response = await sheets.spreadsheets.values.get({
      spreadsheetId,
      range: 'Form Responses 1!A:L',
    });

    const rows = response.data.values;
    if (!rows || rows.length === 0) return res.status(404).json({ success: false, message: 'Database empty' });

    let userFound = false;
    let userData = {};

    for (let i = 1; i < rows.length; i++) {
      const row = rows[i];
      if (row[10] && row[10].toString().trim().toUpperCase() === certIdToCheck) {
        userFound = true;
        userData = {
          name: row[1],
          domain: row[4],
          regId: row[5],
          duration: row[7] || '',
          startDate: row[8] || '',
          endDate: row[9] || '',
          certId: row[10] || '',
          issueDate: row[11] || '',
        };
        break;
      }
    }

    if (!userFound) return res.status(404).json({ success: false, message: 'Invalid Certificate ID. Not found in our records.' });
    return res.json({ success: true, message: 'Certificate is Valid and Verified! ✅', user: userData });
  } catch (error) {
    console.error('Validate Error:', error);
    res.status(500).json({ success: false, message: 'Server error during validation' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Backend Server running on port ${PORT}`);
});