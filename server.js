const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
require('dotenv').config();

const app = express();
const prisma = new PrismaClient();

// ================= RATE LIMITER =================
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Limit each IP to 20 requests per windowMs
  message: { success: false, message: 'Too many requests from this IP, please try again after 15 minutes.' }
});

app.post('/api/auth/login', authLimiter);
app.post('/api/auth/register', authLimiter);
app.post('/api/auth/forgot-password', authLimiter);

app.use(cors({
  origin: ['http://localhost:5173', 'https://velystra-technology.vercel.app'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true
}));

app.use(express.json());

// ================= MIDDLEWARES =================
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });

  jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret', (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
};

const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ success: false, message: 'Access forbidden.' });
    }
    next();
  };
};

const verifyCollegeAdmin = async (req, res, next) => {
  try {
    const user = req.user;
    if (!user) {
      return res.status(401).json({ success: false, message: 'Unauthorized. Please login.' });
    }
    if (user.role !== 'COLLEGE_ADMIN' && user.role !== 'SUPER_ADMIN') {
      return res.status(403).json({ success: false, message: 'Access denied. College Admin role required.' });
    }
    if (user.role === 'COLLEGE_ADMIN') {
      const college = await prisma.college.findFirst({ where: { adminId: user.userId } });
      if (!college) {
        return res.status(403).json({ success: false, message: 'No college managed by this admin.' });
      }
      req.managedCollegeId = college.id; // Multi-tenant isolation ID
    }
    next();
  } catch (err) {
    console.error('Admin Auth Middleware Error:', err);
    res.status(500).json({ success: false, message: 'Authorization error.' });
  }
};

// Brevo Email Helper Function
const sendBrevoEmail = async (toEmail, toName, subject, htmlContent) => {
  if (!process.env.BREVO_API_KEY) {
    console.warn('BREVO_API_KEY not set in environment variables.');
    return;
  }
  await axios.post('https://api.brevo.com/v3/smtp/email', {
    sender: { name: 'Velystra Technology', email: process.env.SENDER_EMAIL || 'no-reply@velystra.com' },
    to: [{ email: toEmail, name: toName }],
    subject: subject,
    htmlContent: htmlContent
  }, {
    headers: {
      'api-key': process.env.BREVO_API_KEY,
      'Content-Type': 'application/json'
    }
  });
};

const auth = new google.auth.GoogleAuth({
  keyFile: 'credentials.json',
  scopes: ['https://www.googleapis.com/auth/spreadsheets'],
});

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// ================= AUTHENTICATION =================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, role, prnNumber, collegeCode, collegeName, domain, avatarUrl, bio } = req.body;
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) return res.status(400).json({ success: false, message: 'User already exists.' });

    const passwordHash = await bcrypt.hash(password, await bcrypt.genSalt(10));
    const newUser = await prisma.user.create({ data: { email, passwordHash, name: name || '', role: role || 'STUDENT' } });

    if (role === 'COLLEGE_ADMIN' && collegeName) {
      const randomCode = Math.floor(100000 + Math.random() * 900000).toString();
      await prisma.college.create({ data: { name: collegeName, code: randomCode, city: 'Pune', state: 'Maharashtra', adminId: newUser.id } });
    }

    if (role === 'STUDENT' && prnNumber && collegeCode) {
      const college = await prisma.college.findUnique({ where: { code: collegeCode.trim() } });
      if (!college) {
        await prisma.user.delete({ where: { id: newUser.id } });
        return res.status(400).json({ success: false, message: 'Invalid College ID!' });
      }

      await prisma.student.create({
        data: {
          userId: newUser.id,
          fullName: name,
          prnNumber: prnNumber.trim(),
          collegeId: college.id,
          domain: domain || 'Full Stack Developer',
          avatarUrl: avatarUrl || '',
          bio: bio || '',
          isApproved: false,
        }
      });
    }

    res.json({ success: true, message: 'Registered successfully!', userId: newUser.id });
  } catch (error) {
    console.error('Register Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(400).json({ success: false, message: 'Invalid email or password.' });
    }

    const token = jwt.sign({ userId: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET || 'fallback', { expiresIn: '7d' });
    let collegeDetails = null;
    if (user.role === 'COLLEGE_ADMIN') {
      collegeDetails = await prisma.college.findFirst({ where: { adminId: user.id } });
    }

    const studentRecord = await prisma.student.findUnique({ where: { userId: user.id } });

    res.json({ success: true, token, user: { id: user.id, email: user.email, name: user.name, role: user.role, college: collegeDetails, student: studentRecord } });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ================= STUDENT PROFILE UPDATE =================
app.put('/api/student/profile', verifyToken, async (req, res) => {
  try {
    const { fullName, avatarUrl, bio, domain } = req.body;
    const updatedStudent = await prisma.student.update({
      where: { userId: req.user.userId },
      data: { fullName, avatarUrl, bio, domain }
    });
    res.json({ success: true, message: 'Profile updated successfully!', updatedStudent });
  } catch (error) {
    console.error('Profile Update Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ================= COLLEGE ADMIN STATS & STUDENTS =================
app.get('/api/admin/stats', verifyToken, verifyCollegeAdmin, async (req, res) => {
  try {
    const collegeId = req.managedCollegeId;
    const students = await prisma.student.findMany({
      where: collegeId ? { collegeId, isApproved: true } : {},
      include: { college: true },
      orderBy: { campusScore: 'desc' }
    });

    res.json({ success: true, totalStudents: students.length, students });
  } catch (error) {
    console.error('Admin Stats Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.get('/api/admin/pending-students', verifyToken, verifyCollegeAdmin, async (req, res) => {
  try {
    const collegeId = req.managedCollegeId;
    const students = await prisma.student.findMany({ 
      where: { collegeId, isApproved: false }, 
      include: { user: { select: { email: true } }, college: true } 
    });
    const managedCollege = await prisma.college.findUnique({ where: { id: collegeId } });

    res.json({ success: true, students, collegeCode: managedCollege?.code || null });
  } catch (error) {
    console.error('Pending Students Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.post('/api/admin/students/:id/approve', verifyToken, verifyCollegeAdmin, async (req, res) => {
  try {
    const student = await prisma.student.update({ where: { id: req.params.id }, data: { isApproved: true }, include: { user: true, college: true } });
    res.json({ success: true, message: 'Student approved!', student });
  } catch (error) {
    console.error('Approve Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.post('/api/super-admin/colleges/:id/approve', verifyToken, async (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') {
    return res.status(403).json({ success: false, message: 'Access denied.' });
  }
  await prisma.college.update({
    where: { id: req.params.id },
    data: { isVerified: true }
  });
  res.json({ success: true, message: 'College approved successfully!' });
});

// ================= CHALLENGES =================
app.post('/api/challenges', verifyToken, verifyCollegeAdmin, async (req, res) => {
  try {
    // 🛑 Check if the college is verified by Super Admin (if it's a college admin creating it)
    if (req.managedCollegeId) {
      const college = await prisma.college.findUnique({ where: { id: req.managedCollegeId } });
      if (!college || !college.isVerified) {
        return res.status(403).json({ 
          success: false, 
          message: 'Your college registration is pending Super Admin verification. You cannot host events yet.' 
        });
      }
    }

    const { title, description, points, deadline } = req.body;
    const challenge = await prisma.challenge.create({
      data: { title, description, points: parseInt(points) || 100, deadline: deadline ? new Date(deadline) : null, collegeId: req.managedCollegeId || null, isActive: true }
    });

    res.json({ success: true, message: 'Challenge created!', challenge });
  } catch (error) {
    console.error('Challenge Create Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.put('/api/admin/challenges/:id', verifyToken, verifyCollegeAdmin, async (req, res) => {
  try {
    // 🛑 Optional: Check verification for editing too
    if (req.managedCollegeId) {
      const college = await prisma.college.findUnique({ where: { id: req.managedCollegeId } });
      if (!college || !college.isVerified) {
        return res.status(403).json({ 
          success: false, 
          message: 'Your college is pending Super Admin verification.' 
        });
      }
    }

    const { title, description, points, deadline, isActive } = req.body;
    const updated = await prisma.challenge.update({
      where: { id: req.params.id },
      data: {
        title,
        description,
        points: points !== undefined ? parseInt(points) : undefined,
        deadline: deadline ? new Date(deadline) : null,
        isActive: isActive !== undefined ? isActive : undefined
      }
    });
    res.json({ success: true, message: 'Challenge updated successfully!', updated });
  } catch (error) {
    console.error('Challenge Update Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.get('/api/challenges', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const userRole = req.user.role;

    if (userRole === 'SUPER_ADMIN' || userRole === 'COLLEGE_ADMIN') {
      const managedCollege = userRole === 'COLLEGE_ADMIN' ? await prisma.college.findFirst({ where: { adminId: userId } }) : null;
      const challenges = await prisma.challenge.findMany({
        where: userRole === 'COLLEGE_ADMIN' && managedCollege ? { collegeId: managedCollege.id } : {},
        include: { 
          college: true,
          submissions: { include: { student: true } }
        },
        orderBy: { createdAt: 'desc' }
      });
      return res.json({ success: true, challenges });
    }

    const student = await prisma.student.findUnique({ where: { userId } });
    if (!student || !student.isApproved) {
      const challenges = await prisma.challenge.findMany({ 
        where: { collegeId: null }, 
        include: { college: true, submissions: true }, 
        orderBy: { createdAt: 'desc' } 
      });
      return res.json({ success: true, challenges, isApproved: false });
    }

    const challenges = await prisma.challenge.findMany({
      where: { OR: [{ collegeId: null }, { collegeId: student.collegeId }] },
      include: { college: true, submissions: true },
      orderBy: { createdAt: 'desc' }
    });

    res.json({ success: true, challenges, isApproved: true });
  } catch (error) {
    console.error('Fetch Challenges Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ================= SMART SUBMISSIONS & HISTORY =================
app.post('/api/submissions', verifyToken, async (req, res) => {
  try {
    const { challengeId, githubUrl, deployedUrl } = req.body;
    const student = await prisma.student.findUnique({ where: { userId: req.user.userId } });
    if (!student || !student.isApproved) return res.status(403).json({ success: false, message: 'PRN must be approved first.' });

    const existing = await prisma.submission.findFirst({
      where: { studentId: student.id, challengeId }
    });

    if (existing) {
      if (existing.status === 'APPROVED') {
        return res.status(400).json({ success: false, message: 'Points already awarded! Please try other events.' });
      }
      if (existing.status === 'PENDING') {
        return res.status(400).json({ success: false, message: 'Your submission is already pending review.' });
      }
      if (existing.status === 'REJECTED') {
        const updated = await prisma.submission.update({
          where: { id: existing.id },
          data: { githubUrl, deployedUrl, status: 'PENDING', feedback: null }
        });
        return res.json({ success: true, message: 'Re-submitted successfully! Pending review. ⏳', submission: updated });
      }
    }

    const submission = await prisma.submission.create({ data: { studentId: student.id, challengeId, githubUrl, deployedUrl, status: 'PENDING', scoreAwarded: 0 } });
    res.json({ success: true, message: 'Submitted successfully! ⏳', submission });
  } catch (error) {
    console.error('Submission Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.get('/api/admin/submissions', verifyToken, verifyCollegeAdmin, async (req, res) => {
  try {
    let whereCondition = { status: 'PENDING' };
    if (req.user.role === 'COLLEGE_ADMIN') {
      whereCondition.student = { collegeId: req.managedCollegeId };
    }
    const submissions = await prisma.submission.findMany({ where: whereCondition, include: { challenge: true, student: { include: { college: true } } } });
    res.json({ success: true, submissions });
  } catch (error) {
    console.error('Submissions Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.post('/api/admin/submissions/:id/approve', verifyToken, verifyCollegeAdmin, async (req, res) => {
  try {
    const sub = await prisma.submission.findUnique({ where: { id: req.params.id }, include: { challenge: true } });
    const updated = await prisma.submission.update({ where: { id: req.params.id }, data: { status: 'APPROVED', scoreAwarded: sub.challenge.points } });
    await prisma.student.update({ where: { id: sub.studentId }, data: { campusScore: { increment: sub.challenge.points } } });
    res.json({ success: true, message: 'Approved!', updated });
  } catch (error) {
    console.error('Approve Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.post('/api/admin/submissions/:id/reject', verifyToken, verifyCollegeAdmin, async (req, res) => {
  try {
    const { feedback } = req.body;
    const updated = await prisma.submission.update({
      where: { id: req.params.id },
      data: { status: 'REJECTED', feedback: feedback || 'Submission rejected by admin.' }
    });
    res.json({ success: true, message: 'Submission rejected with feedback.', updated });
  } catch (error) {
    console.error('Reject Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// Student Stats & Points History
app.get('/api/student/stats', verifyToken, async (req, res) => {
  try {
    const student = await prisma.student.findUnique({
      where: { userId: req.user.userId },
      include: {
        submissions: {
          include: { challenge: true }
        }
      }
    });

    if (!student) return res.status(404).json({ success: false, message: 'Student not found.' });

    let collegePoints = 0;
    let publicPoints = 0;

    student.submissions.forEach(sub => {
      if (sub.status === 'APPROVED') {
        if (sub.challenge.collegeId !== null) {
          collegePoints += sub.scoreAwarded;
        } else {
          publicPoints += sub.scoreAwarded;
        }
      }
    });

    res.json({ success: true, student, collegePoints, publicPoints, submissions: student.submissions });
  } catch (error) {
    console.error('Student Stats Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ================= LEADERBOARD (Global & College Specific with Tie-Breaker) =================
app.get('/api/leaderboard', verifyToken, async (req, res) => {
  try {
    const { type } = req.query; // 'college' or 'global'
    const user = req.user;

    let whereCondition = {};
    if (type === 'college' && user.role === 'STUDENT') {
      const student = await prisma.student.findUnique({ where: { userId: user.userId } });
      if (student) whereCondition.collegeId = student.collegeId;
    } else if (user.role === 'COLLEGE_ADMIN') {
      const managedCollege = await prisma.college.findFirst({ where: { adminId: user.userId } });
      if (managedCollege) whereCondition.collegeId = managedCollege.id;
    }

    // Fetch students sorted by total campusScore (College + Public combined points)
    const rawLeaderboard = await prisma.student.findMany({
      where: whereCondition,
      orderBy: [
        { campusScore: 'desc' }, // 1st Priority: Highest Combined Score
        { createdAt: 'asc' }     // 2nd Priority (Tie-Breaker): Earliest registration
      ],
      take: 20, // Top 20 for global excitement
      include: { 
        college: { select: { name: true, city: true } },
        submissions: { include: { challenge: true } } // Include submissions to split stats if needed
      },
    });

    // Format data to include split points (College Points vs Public Points) for transparency
    const leaderboard = rawLeaderboard.map(student => {
      let collegePoints = 0;
      let publicPoints = 0;

      student.submissions.forEach(sub => {
        if (sub.status === 'APPROVED') {
          if (sub.challenge.collegeId !== null) {
            collegePoints += sub.scoreAwarded;
          } else {
            publicPoints += sub.scoreAwarded;
          }
        }
      });

      return {
        id: student.id,
        fullName: student.fullName,
        avatarUrl: student.avatarUrl,
        domain: student.domain,
        campusScore: student.campusScore, // Total Score
        collegePoints,
        publicPoints,
        college: student.college
      };
    });

    res.json({ success: true, leaderboard });
  } catch (error) {
    console.error('Leaderboard Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ================= FORGOT PASSWORD =================
app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(404).json({ success: false, message: 'Email not registered in the system.' });
    }

    const tempPassword = Math.random().toString(36).slice(-8);
    const passwordHash = await bcrypt.hash(tempPassword, await bcrypt.genSalt(10));
    await prisma.user.update({ where: { email }, data: { passwordHash } });

    try {
      await sendBrevoEmail(
        email, 
        user.name, 
        'Password Reset - Velystra Technology', 
        `<p>Hello ${user.name},</p><p>Your temporary password is: <strong>${tempPassword}</strong></p><p>Please login and update your password immediately.</p>`
      );
    } catch (emailErr) {
      console.error('Brevo Email Send Error:', emailErr);
    }

    res.json({ 
      success: true, 
      message: 'Password reset successful! A temporary password has been sent to your registered email.'
    });
  } catch (error) {
    console.error('Forgot Password Error:', error);
    res.status(500).json({ success: false, message: 'Server error during password reset.' });
  }
});

// ================= PUBLIC STUDENT PROFILE VIEW =================
app.get('/api/student/:id/profile', async (req, res) => {
  try {
    const student = await prisma.student.findUnique({
      where: { id: req.params.id },
      include: {
        college: true,
        submissions: { where: { status: 'APPROVED' }, include: { challenge: true } }
      }
    });

    if (!student) return res.status(404).json({ success: false, message: 'Student not found.' });

    res.json({ success: true, student });
  } catch (error) {
    console.error('Public Profile Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Backend Server running on port ${PORT}`));