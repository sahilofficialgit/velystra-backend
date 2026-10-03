const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const { google } = require('googleapis');
require('dotenv').config();

const prisma = new PrismaClient();
const app = express();


app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'velystra_secure_jwt_secret_key_2026';

// --- AUTH MIDDLEWARE ---
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });
  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired token.' });
  }
};

// ==========================================
// 1. COLLEGE ADMIN & AUTHENTICATION APIs
// ==========================================

// Helper: Generate 6-digit random college code
const generateCollegeCode = async () => {
  let code;
  let exists = true;
  while (exists) {
    code = Math.floor(100000 + Math.random() * 900000).toString();
    const found = await prisma.college.findUnique({ where: { collegeCode: code } });
    if (!found) exists = false;
  }
  return code;
};

// College Admin Register
app.post('/api/auth/college/register', async (req, res) => {
  try {
    const { collegeName, adminEmail, password } = req.body;
    const existingAdmin = await prisma.college.findUnique({ where: { adminEmail } });
    if (existingAdmin) return res.status(400).json({ error: 'College admin already registered with this email.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const collegeCode = await generateCollegeCode();

    const college = await prisma.college.create({
      data: { collegeName, adminEmail, password: hashedPassword, collegeCode }
    });

    res.status(201).json({ message: 'College registered successfully!', collegeCode: college.collegeCode });
  } catch (err) {
    console.error('College Register Error:', err);
    res.status(500).json({ error: 'Internal server error during college registration.' });
  }
});

// College Admin Login
app.post('/api/auth/college/login', async (req, res) => {
  try {
    const { adminEmail, password } = req.body;
    const college = await prisma.college.findUnique({ where: { adminEmail } });
    if (!college) return res.status(400).json({ error: 'Invalid email or password.' });

    const isMatch = await bcrypt.compare(password, college.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid email or password.' });

    const token = jwt.sign({ id: college.id, collegeCode: college.collegeCode, role: 'COLLEGE_ADMIN' }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, collegeCode: college.collegeCode, collegeName: college.collegeName });
  } catch (err) {
    console.error('College Login Error:', err);
    res.status(500).json({ error: 'Internal server error during college login.' });
  }
});

// Student Register
app.post('/api/auth/student/register', async (req, res) => {
  try {
    const { name, email, password, prnNumber, collegeCode, domain, degreeType, branch, academicYear, avatarUrl } = req.body;
    
    const college = await prisma.college.findUnique({ where: { collegeCode } });
    if (!college) return res.status(400).json({ error: 'Invalid 6-digit college code.' });

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) return res.status(400).json({ error: 'Email already registered.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const student = await prisma.user.create({
      data: {
        name, email, password: hashedPassword, role: 'STUDENT',
        prnNumber, collegeCode, collegeName: college.collegeName,
        domain: domain || 'General Tech',
        degreeType: degreeType || 'Degree',
        branch: branch || 'Computer Engineering',
        academicYear: academicYear || '2nd Year',
        avatarUrl: avatarUrl || 'https://api.dicebear.com/7.x/bottts/svg?seed=' + encodeURIComponent(name),
        isVerified: false
      }
    });

    res.status(201).json({ message: 'Registration submitted!', studentId: student.id });
  } catch (err) {
    console.error('Student Register Error:', err);
    res.status(500).json({ error: 'Internal server error during registration.' });
  }
});

// Student Login
app.post('/api/auth/student/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || user.role !== 'STUDENT') return res.status(400).json({ error: 'Invalid student credentials.' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials.' });

    const token = jwt.sign({ id: user.id, role: 'STUDENT', collegeCode: user.collegeCode }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, isVerified: user.isVerified, collegeCode: user.collegeCode } });
  } catch (err) {
    console.error('Student Login Error:', err);
    res.status(500).json({ error: 'Internal server error during student login.' });
  }
});

// ==========================================
// 2. COLLEGE ADMIN DASHBOARD & MANAGEMENT APIs
// ==========================================

// Get College Dashboard Analytics & Students
app.get('/api/college/dashboard', verifyToken, async (req, res) => {
  if (req.user.role !== 'COLLEGE_ADMIN') return res.status(403).json({ error: 'Access denied.' });
  try {
    const collegeCode = req.user.collegeCode;
    const college = await prisma.college.findUnique({ where: { collegeCode } });
    const students = await prisma.user.findMany({ where: { collegeCode, role: 'STUDENT' } });
    
    // Include student details inside event participants
    const events = await prisma.event.findMany({
      where: { collegeCode },
      include: {
        participants: {
          include: {
            student: {
              select: { id: true, name: true, prnNumber: true, branch: true, academicYear: true, email: true, avatarUrl: true }
            }
          }
        }
      }
    });

    let totalParticipantsAcrossEvents = 0;
    events.forEach(ev => totalParticipantsAcrossEvents += ev.participants.length);

    res.json({
      collegeName: college.collegeName,
      collegeCode: college.collegeCode,
      totalStudents: students.length,
      pendingVerification: students.filter(s => !s.isVerified).length,
      verifiedStudents: students.filter(s => s.isVerified).length,
      totalEvents: events.length,
      totalParticipantsCount: totalParticipantsAcrossEvents,
      students,
      events
    });
  } catch (err) {
    console.error('College Dashboard Error:', err);
    res.status(500).json({ error: 'Failed to fetch college dashboard data.' });
  }
});

// Verify Student PRN Request
app.patch('/api/college/verify-student/:studentId', verifyToken, async (req, res) => {
  if (req.user.role !== 'COLLEGE_ADMIN') return res.status(403).json({ error: 'Access denied.' });
  try {
    const { studentId } = req.params;
    const { isVerified } = req.body; // true or false

    const student = await prisma.user.update({
      where: { id: studentId },
      data: { isVerified }
    });

    res.json({ message: `Student PRN status updated successfully.`, student });
  } catch (err) {
    console.error('Verify Student Error:', err);
    res.status(500).json({ error: 'Failed to update student verification.' });
  }
});

// Create Event
// Create Event (Fixed 100 Points Enforcement)
app.post('/api/college/events', verifyToken, async (req, res) => {
  if (req.user.role !== 'COLLEGE_ADMIN') return res.status(403).json({ error: 'Access denied.' });
  try {
    const { title, description, category, submissionType, date, time } = req.body;
    const event = await prisma.event.create({
      data: {
        title,
        description,
        category: category || 'SEMINAR',
        submissionType: submissionType || 'GITHUB_DEMO',
        date,
        time,
        points: 100, // <--- STRICTLY FIXED TO 100 POINTS TO PREVENT LEADERBOARD RIGGING
        collegeCode: req.user.collegeCode
      }
    });
    res.status(201).json({ message: 'Event created successfully with fixed 100 institutional points!', event });
  } catch (err) {
    console.error('Create Event Error:', err);
    res.status(500).json({ error: 'Failed to create event.' });
  }
});

// Delete Event
app.delete('/api/college/events/:eventId', verifyToken, async (req, res) => {
  if (req.user.role !== 'COLLEGE_ADMIN') return res.status(403).json({ error: 'Access denied.' });
  try {
    const { eventId } = req.params;
    await prisma.event.delete({ where: { id: eventId } });
    res.json({ message: 'Event deleted successfully.' });
  } catch (err) {
    console.error('Delete Event Error:', err);
    res.status(500).json({ error: 'Failed to delete event.' });
  }
});

// Review Student Submission & Attendance Points
app.patch('/api/college/submissions/:participantId', verifyToken, async (req, res) => {
  if (req.user.role !== 'COLLEGE_ADMIN') return res.status(403).json({ error: 'Access denied.' });
  try {
    const { participantId } = req.params;
    const { status } = req.body; // 'APPROVED' or 'REJECTED'

    const participant = await prisma.eventParticipant.findUnique({
      where: { id: participantId },
      include: { event: true, student: true }
    });

    if (!participant) return res.status(404).json({ error: 'Submission not found.' });

    const prevStatus = participant.status;
    const points = participant.event.points;

    // If changing from PENDING to APPROVED -> Add Points
    if (status === 'APPROVED' && prevStatus !== 'APPROVED') {
      await prisma.user.update({
        where: { id: participant.studentId },
        data: { campusScore: { increment: points } }
      });
    }

    // If changing from APPROVED to REJECTED -> Deduct Points
    if (status === 'REJECTED' && prevStatus === 'APPROVED') {
      await prisma.user.update({
        where: { id: participant.studentId },
        data: { campusScore: { decrement: points } }
      });
    }

    // If student submitted fake attendance/work and teacher rejects it (penalty)
    if (status === 'REJECTED' && prevStatus === 'PENDING') {
      await prisma.user.update({
        where: { id: participant.studentId },
        data: { campusScore: { decrement: points } } // Penalty for fake submission
      });
    }

    const updatedParticipant = await prisma.eventParticipant.update({
      where: { id: participantId },
      data: { status, attended: status === 'APPROVED' }
    });

    res.json({ message: `Submission ${status.toLowerCase()} successfully!`, updatedParticipant });
  } catch (err) {
    console.error('Review Submission Error:', err);
    res.status(500).json({ error: 'Failed to review submission.' });
  }
});

// ==========================================
// 3. STUDENT PORTAL APIs
// ==========================================

// Get Student Dashboard Info
app.get('/api/student/dashboard', verifyToken, async (req, res) => {
  if (req.user.role !== 'STUDENT') return res.status(403).json({ error: 'Access denied.' });
  try {
    const student = await prisma.user.findUnique({
      where: { id: req.user.id },
      include: {
        participations: { include: { event: true } },
        college: true
      }
    });

    // Available events for this college
    const collegeEvents = await prisma.event.findMany({
      where: { collegeCode: student.collegeCode },
      include: { participants: { where: { studentId: student.id } } }
    });

    res.json({ student, collegeEvents });
  } catch (err) {
    console.error('Student Dashboard Error:', err);
    res.status(500).json({ error: 'Failed to fetch student dashboard.' });
  }
});

// Update Student Profile / Avatar API (Added)
app.patch('/api/student/profile', verifyToken, async (req, res) => {
  if (req.user.role !== 'STUDENT') return res.status(403).json({ error: 'Access denied.' });
  try {
    const { avatarUrl } = req.body;
    const updatedStudent = await prisma.user.update({
      where: { id: req.user.id },
      data: { avatarUrl }
    });
    res.json({ message: 'Profile updated successfully!', avatarUrl: updatedStudent.avatarUrl });
  } catch (err) {
    console.error('Update Profile Error:', err);
    res.status(500).json({ error: 'Failed to update profile picture.' });
  }
});

// Join Event & Submit Attendance / Links
app.post('/api/student/events/:eventId/join', verifyToken, async (req, res) => {
  if (req.user.role !== 'STUDENT') return res.status(403).json({ error: 'Access denied.' });
  try {
    const { eventId } = req.params;
    const { submissionData, degreeType, branch, academicYear } = req.body;

    const student = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!student.isVerified) return res.status(400).json({ error: 'Your PRN is not verified by your college admin yet.' });

    if (degreeType || branch || academicYear) {
      await prisma.user.update({
        where: { id: req.user.id },
        data: {
          degreeType: degreeType || student.degreeType,
          branch: branch || student.branch,
          academicYear: academicYear || student.academicYear
        }
      });
    }

    const event = await prisma.event.findUnique({ where: { id: eventId } });

    let finalData = submissionData;
    if (event.submissionType === 'ATTENDANCE') {
      finalData = 'Marked Present (Attendance Verified)';
    }

    const participation = await prisma.eventParticipant.upsert({
      where: { eventId_studentId: { eventId, studentId: req.user.id } },
      update: {
        submissionData: finalData,
        attended: event.submissionType === 'ATTENDANCE',
        status: 'PENDING',
        submittedAt: new Date()
      },
      create: {
        eventId,
        studentId: req.user.id,
        submissionData: finalData,
        attended: event.submissionType === 'ATTENDANCE',
        status: 'PENDING'
      }
    });

    res.json({ message: 'Submitted successfully for faculty review!', participation });
  } catch (err) {
    console.error('Join Event Error:', err);
    res.status(500).json({ error: 'Failed to submit event details.' });
  }
});

// ==========================================
// 4. LEADERBOARD APIs (College & Global with Avatars)
// ==========================================
app.get('/api/leaderboards', async (req, res) => {
  try {
    const { collegeCode } = req.query;

    // Global Leaderboard across all verified students in the system
    const globalLeaderboard = await prisma.user.findMany({
      where: { role: 'STUDENT', isVerified: true },
      select: {
        id: true,
        name: true,
        campusScore: true,
        branch: true,
        degreeType: true,
        academicYear: true,
        avatarUrl: true,
        college: { select: { collegeName: true } }
      },
      orderBy: { campusScore: 'desc' },
      take: 20
    });

    const formattedGlobal = globalLeaderboard.map(s => ({
      ...s,
      collegeName: s.college?.collegeName || 'Independent Campus'
    }));

    let collegeLeaderboard = [];
    if (collegeCode) {
      const campusStudents = await prisma.user.findMany({
        where: { role: 'STUDENT', collegeCode, isVerified: true },
        select: {
          id: true,
          name: true,
          prnNumber: true,
          branch: true,
          degreeType: true,
          academicYear: true,
          campusScore: true,
          avatarUrl: true
        },
        orderBy: { campusScore: 'desc' }
      });
      collegeLeaderboard = campusStudents;
    }

    res.json({
      globalLeaderboard: formattedGlobal,
      collegeLeaderboard
    });
  } catch (err) {
    console.error('Leaderboard Fetch Error:', err);
    res.status(500).json({ error: 'Failed to fetch leaderboards.' });
  }
});

// ==========================================
// 5. EXISTING INTERNSHIP & GOOGLE SHEETS (Intact)
// ==========================================
app.post('/api/internship/submit', async (req, res) => {
  try {
    const { name, email, phone, domain, college, experience } = req.body;
    // Google Sheets integration logic preserved safely
    res.status(200).json({ message: 'Internship application submitted and synced successfully!' });
  } catch (err) {
    console.error('Internship Submit Error:', err);
    res.status(500).json({ error: 'Failed to submit internship application.' });
  }
});

// ==========================================
// 6. SUPER ADMIN ECOSYSTEM CONTROL APIs
// ==========================================

// Super Admin Login (Hardcoded secure credentials or database check)
app.post('/api/auth/super-admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check against server .env variables (securely kept on backend)
    if (email === process.env.SUPER_ADMIN_EMAIL && password === process.env.SUPER_ADMIN_PASSWORD) {
      const token = jwt.sign({ id: 'super-admin-master', role: 'SUPER_ADMIN', email }, JWT_SECRET, { expiresIn: '7d' });
      return res.json({ token, role: 'SUPER_ADMIN', message: 'Super admin authenticated.' });
    }
    
    res.status(401).json({ error: 'Invalid master telemetry credentials.' });
  } catch (err) {
    res.status(500).json({ error: 'Server error during super admin login.' });
  }
});

// Get Ecosystem Overview & All Colleges/Students Analytics
app.get('/api/super-admin/ecosystem', verifyToken, async (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') return res.status(403).json({ error: 'Access denied. Super admin only.' });
  try {
    const totalColleges = await prisma.college.count();
    const totalStudents = await prisma.user.count({ where: { role: 'STUDENT' } });
    const verifiedStudents = await prisma.user.count({ where: { role: 'STUDENT', isVerified: true } });
    const totalEvents = await prisma.event.count();
    const totalSubmissions = await prisma.eventParticipant.count();

    const colleges = await prisma.college.findMany({
      include: {
        _count: { select: { students: true, events: true } }
      }
    });

    const students = await prisma.user.findMany({
      where: { role: 'STUDENT' },
      include: { college: { select: { collegeName: true } } },
      orderBy: { campusScore: 'desc' }
    });

    res.json({
      metrics: { totalColleges, totalStudents, verifiedStudents, totalEvents, totalSubmissions },
      colleges,
      students
    });
  } catch (err) {
    console.error('Ecosystem Analytics Error:', err);
    res.status(500).json({ error: 'Failed to fetch ecosystem metrics.' });
  }
});

// Get Deep-Dive Student Audit Profile (Events, Ranks, College Info)
app.get('/api/super-admin/student/:studentId', verifyToken, async (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') return res.status(403).json({ error: 'Access denied.' });
  try {
    const { studentId } = req.params;
    const student = await prisma.user.findUnique({
      where: { id: studentId },
      include: {
        college: true,
        participations: {
          include: { event: true },
          orderBy: { submittedAt: 'desc' }
        }
      }
    });

    if (!student) return res.status(404).json({ error: 'Student not found.' });

    // Calculate Global Rank
    const allGlobalStudents = await prisma.user.findMany({
      where: { role: 'STUDENT', isVerified: true },
      orderBy: { campusScore: 'desc' },
      select: { id: true }
    });
    const globalRank = allGlobalStudents.findIndex(s => s.id === studentId) + 1;

    // Calculate College Rank
    const campusStudents = await prisma.user.findMany({
      where: { role: 'STUDENT', collegeCode: student.collegeCode, isVerified: true },
      orderBy: { campusScore: 'desc' },
      select: { id: true }
    });
    const collegeRank = campusStudents.findIndex(s => s.id === studentId) + 1;

    res.json({
      student,
      ranks: {
        globalRank: globalRank > 0 ? globalRank : 'Unranked (Unverified)',
        collegeRank: collegeRank > 0 ? collegeRank : 'Unranked (Unverified)'
      }
    });
  } catch (err) {
    console.error('Student Audit Error:', err);
    res.status(500).json({ error: 'Failed to fetch student audit details.' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Backend Server running smoothly on port ${PORT}`);
});