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

    // 🔄 ORIGINAL PRICING LOGIC RESTORED
    let finalAmount = 150;
    if (userDuration.includes('3')) {
      finalAmount = deliveryOption === 'printed' ? 450 : 300;
    } else if (userDuration.includes('6')) {
      finalAmount = deliveryOption === 'printed' ? 700 : 500;
    } else {
      finalAmount = deliveryOption === 'printed' ? 299 : 150;
    }

    const options = {
      amount: finalAmount * 100, // Amount in paise
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