// ------------------- MODULES -------------------
require('dotenv').config();
const express = require('express');
const session = require('express-session');
// FIX 1: Added missing library for session storage
const pgSession = require('connect-pg-simple')(session); 
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const path = require('path');

// ------------------- APP SETUP -------------------
const app = express();

// Serve static files (CSS, JS, images)
app.use(express.static(path.join(__dirname, 'public')));

// PostgreSQL connections – ONLY ONE AT A TIME

// FOR AWS –––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––


// const pool = new Pool({
//   host: process.env.DB_HOST,
//   port: process.env.DB_PORT,
//   user: process.env.DB_USER,
//   password: process.env.DB_PASSWORD,
//   database: process.env.DB_NAME,
//   // The Switch: Only use SSL if the environment variable asks for it
//   ssl: {
//     rejectUnauthorized: false  // For RDS
//   }   // { rejectUnauthorized: false } : false
// });


// FOR LOCALHOST ––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––


const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  // SSL is completely removed for local development
});

// ––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––


// Test database connection
pool.connect((err) => {
  if (err) {
    console.error('❌ Database connection failed:', err);
  } else {
    console.log('✅ Database connected successfully');
  }
});

// ------------------- SESSION SETUP -------------------
app.use(
  session({
    store: new pgSession({
      pool, // Use your PostgreSQL connection
      tableName: 'session',
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET || 'intex',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // false for localhost
      httpOnly: false, // allow cookies in browser during dev
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);

// ------------------- MIDDLEWARE -------------------
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Set EJS view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Debugging middleware to track session
app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  console.log(
    'Session check:',
    req.session.user
      ? `✅ logged in as ${req.session.user.email}`
      : '❌ not logged in'
  );
  next();
});

// ------------------- AUTH MIDDLEWARE -------------------
function requireLogin(req, res, next) {
  if (req.session.user) next();
  else res.redirect('/login');
}

function requireManager(req, res, next) {
  if (req.session.user && req.session.user.role === 'admin') next();
  else res.status(403).send('Unauthorized: Admins only');
}

// Allow managers OR the logged-in user to access their own data
function requireSelfOrManager(req, res, next) {
  if (!req.session.user) return res.redirect('/login');

  const loggedInUserId = req.session.user.id;  // comes from session
  const targetUserId = parseInt(req.params.id); // comes from route like /participants/:id

  if (req.session.user.role === 'admin' || loggedInUserId === targetUserId) {
    next();
  } else {
    res.status(403).send('Access denied: you can only view your own data.');
  }
}


// ------------------- PUBLIC ROUTES -------------------
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user || null });
});

// ------------------- LOGIN ROUTES -------------------
app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.render('login', { error_message: null, success_message: null });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Query user from the database
    const result = await pool.query(
      'SELECT user_id, email, password, role, first_name, last_name, is_active FROM users WHERE username = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.render('login', {
        error_message: 'Invalid email or password',
        success_message: null,
      });
    }

    const user = result.rows[0];

    if (!user.is_active) {
      return res.render('login', {
        error_message: 'Your account has been deactivated',
        success_message: null,
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.render('login', {
        error_message: 'Invalid email or password',
        success_message: null,
      });
    }

    // Update last login time
    await pool.query('UPDATE users SET last_login = NOW() WHERE user_id = $1', [
      user.user_id,
    ]);

    // Store session data
    req.session.user = {
      id: user.user_id,
      username: user.email,
      role: user.role,
      first_name: user.first_name,
      last_name: user.last_name,
    };

    console.log('✅ Login successful:', user.email);
    req.session.save((err) => {
      if (err) console.error('❌ Session save error:', err);
     
      else console.log('💾 Session saved for:', user.email);
     
      res.redirect('/dashboard');
    });
  } catch (err) {
    console.error('❌ Login error:', err);
    res.render('login', {
      error_message: 'An error occurred. Please try again.',
      success_message: null,
    });
  }
});

// Registering view
app.get('/register', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.render('register', { error_message: null, success_message: null });
});

app.post('/register', async (req, res) => {
  const { first_name, last_name, email, password } = req.body;

  try {
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.render('register', { message: 'Email already registered' });
    }

    // --- CHANGE STARTS HERE ---
    // Hash the password with a salt round of 10
    const hashedPassword = await bcrypt.hash(password, 10);

    const insertQuery = `
      INSERT INTO users (first_name, last_name, email, username, password)
      VALUES ($1, $2, $3, $4, $5)
    `;
   
    // Insert 'hashedPassword' instead of the plain 'password'
    await pool.query(insertQuery, [first_name, last_name, email, email, hashedPassword]);
    // --- CHANGE ENDS HERE ---

    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.status(500).send("Server Error");
  }
});

// ------------------- LOGOUT -------------------
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('Logout error:', err);
    res.redirect('/');
  });
});

// ------------------- DASHBOARD -------------------
app.get('/dashboard', requireLogin, async (req, res) => {
  try {
    // Query your database for the statistics
    const totalParticipants = await pool.query('SELECT COUNT(*) as count FROM users');
    const regularUsers = await pool.query('SELECT COUNT(*) as count FROM users WHERE role = $1', ['user']);
    const admins = await pool.query('SELECT COUNT(*) as count FROM users WHERE role = $1', ['admin']);
    const totalDonations = await pool.query('SELECT SUM(amount) as total FROM donations');

    // Debug logging
    console.log('Total Participants:', totalParticipants.rows);
    console.log('Regular Users:', regularUsers.rows);
    console.log('Admins:', admins.rows);
    console.log('Total Donations:', totalDonations.rows);

    // Pass the data to your EJS template with safety checks
    res.render('dashboard', {
      user: req.session.user,
      stats: {
        totalParticipants: totalParticipants.rows[0]?.count || 0,
        regularUsers: regularUsers.rows[0]?.count || 0,
        admins: admins.rows[0]?.count || 0,
        totalDonations: totalDonations.rows[0]?.total || 0
      }
    });
  } catch (error) {
    console.error('Error fetching statistics:', error);
    res.status(500).send('Error loading statistics');
  }
});

// ------------------- USER/PARTICIPANT MANAGEMENT -------------------
// Note: Since we merged tables, managing "users" and "participants" is the same thing.

app.get('/participants', requireLogin, async (req, res) => {
  try {
    const { search = '' } = req.query;
    let result;

    if (req.session.user.role === 'admin') {
      // Managers view all users who are NOT managers (participants)
      const params = [];
      let p = 1;
      let where = [];

      if (search && search.trim() !== '') {
        where.push(`(first_name ILIKE $${p} OR last_name ILIKE $${p} OR email ILIKE $${p})`);
        params.push(`%${search.trim()}%`);
        p++;
      }

      const sql = `
        SELECT user_id, first_name, last_name, email, phone, school_or_employer, field_of_interest, date_of_birth
        FROM users
        ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
        ORDER BY last_name ASC
      `;
      result = await pool.query(sql, params);

    } else {
      // Regular users view themselves
      result = await pool.query(`
        SELECT user_id, first_name, last_name, email, phone, school_or_employer, field_of_interest, date_of_birth
        FROM users
        WHERE user_id = $1
      `, [req.session.user.id]);
    }

    // Mapping fields to match EJS expectations
    const participants = result.rows.map(u => ({
      user_id: u.user_id,
      first_name: u.first_name,
      last_name: u.last_name,
      email: u.email,
      phone: u.phone,
      school_or_employer: u.school_or_employer,
      field_of_interest: u.field_of_interest,
      date_of_birth: u.date_of_birth
    }));

    res.render('participants', { participants, filters: { search } });
  } catch (err) {
    console.error('❌ Error fetching participants:', err.message);
    res.status(500).send('Error loading participants page.');
  }
});

// GET route to show the add user form
app.get('/add_user', requireLogin, requireManager, (req, res) => {
  res.render('add_user', { user: req.session.user });
});

// Your existing POST route
app.post('/add_user', requireLogin, requireManager, async (req, res) => {
  const { first_name, last_name, email, phone, date_of_birth, school_or_employer, field_of_interest } = req.body;
  try {
    const dummyHash = '$2b$10$dummyhashformigratedusers00000000000000000000000000000';
    
    await pool.query(
      `INSERT INTO users (password, email, first_name, last_name, phone, date_of_birth, school_or_employer, field_of_interest, role, is_active)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'user', true)`,
      [email, dummyHash, email, first_name, last_name, phone, date_of_birth, school_or_employer, field_of_interest]
    );
    
    res.redirect('/participants');
  } catch (err) {
    console.error('Error adding participant:', err);
    res.status(500).send('Error adding participant');
  }
});

app.get('/edit-user/:id', requireLogin, requireManager, async (req, res) => {
  const id = req.params.id;
  try {
    const result = await pool.query('SELECT * FROM users WHERE user_id = $1', [id]);
    if (result.rows.length > 0)
      // FIX HERE: Change 'participant' to 'user'
      res.render('edit-user', { user: result.rows[0] }); 
    else res.send('User not found');
  } catch (err) {
    console.error(err);
    res.send('Error loading user'); // Cleaned up the message too
  }
});

app.post('/edit-user/:id', requireLogin, requireManager, async (req, res) => {
  const id = req.params.id;
  const { first_name, last_name, email, phone, school_or_employer, field_of_interest } = req.body;
  try {
    await pool.query(
      `UPDATE users 
       SET first_name=$1, last_name=$2, email=$3, username=$3, phone=$4, school_or_employer=$5, field_of_interest=$6 
       WHERE user_id=$7`,
      [first_name, last_name, email, phone, school_or_employer, field_of_interest, id]
    );
    res.redirect('/participants');
  } catch (err) {
    console.error(err);
    res.send('Error updating participant');
  }
});

app.post('/delete-user/:id', requireLogin, requireManager, async (req, res) => {
  const id = req.params.id;
  try {
    await pool.query('DELETE FROM users WHERE user_id=$1', [id]);
    res.redirect('/participants');
  } catch (err) {
    console.error(err);
    res.send('Error deleting participant');
  }
});


// ===============================================================
// EVENTS PAGE (JOINED QUERY)
// ===============================================================
app.get('/events', requireLogin, async (req, res) => {
  try {
    const { search = '', category = 'All' } = req.query;

    const where = [];
    const params = [];
    let p = 1;

    // Filter by future events
    // NOTE: Commented out so you can see past events (or test data).
    // Uncomment the line below when you are ready for production.
    // where.push(`(ei.start_time >= NOW())`);

    if (category && category !== 'All') {
      where.push(`m.event_type = $${p++}`);
      params.push(category);
    }
    
    if (search && search.trim() !== '') {
      where.push(`(m.event_name ILIKE $${p} OR m.event_description ILIKE $${p} OR ei.location ILIKE $${p})`);
      params.push(`%${search.trim()}%`);
      p++;
    }

    // JOIN master_events with event_instances
    const sql = `
      SELECT 
        ei.event_instance_id,
        m.event_name AS title,
        m.event_type AS category,
        m.event_description AS description,
        ei.start_time AS start_at,
        ei.end_time AS end_at,
        ei.location AS location_name,
        -- REMOVED: ei.city and ei.state (Because they do not exist in the DB)
        ei.capacity
      FROM event_instances ei
      JOIN master_events m ON ei.master_event_id = m.master_event_id
      ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
      ORDER BY ei.start_time ASC
    `;

    const result = await pool.query(sql, params);
    res.render('events', { user: req.session.user, events: result.rows, filters: { search, category } });

  } catch (err) {
    console.error('❌ Error loading events:', err);
    res.status(500).send('Error loading events page.');
  }
});



// ------------------- DONATIONS PAGE -------------------
app.get('/donations', async (req, res) => { // You might want to add 'requireLogin' here
  try {
    const result = await pool.query(`
        SELECT 
            d.donation_id,
            u.first_name || ' ' || u.last_name AS donor_name,
            d.amount,
            d.donation_date AS date
        FROM donations d
        JOIN users u ON d.user_id = u.user_id
        ORDER BY d.donation_date DESC
        LIMIT 50
    `);

    const donations = result.rows.length > 0 ? result.rows : [];

    // UPDATED LINE BELOW:
    // Pass 'user: req.session.user' so the EJS file can read first_name and last_name
    res.render('donations', { donations, user: req.session.user });

  } catch (err) {
    console.error('Error loading donations page:', err);
    res.send('Error loading donations page.');
  }
});

// ------------------- SURVEYS -------------------

// Display all registrations and survey data (Manager) or user's own (User)
app.get('/surveys', requireLogin, async (req, res) => {
  try {
    let result;
    
    // Base SQL fragment for all registrations (surveys)
    const baseQuery = `
        SELECT 
            r.registration_id,
            r.status AS registration_status,
            r.check_in_time,
            r.survey_satisfaction,
            r.survey_comments,
            u.user_id,
            u.first_name, 
            u.last_name, 
            me.event_name AS event_title,      -- Title from MasterEvents
            ei.start_time AS event_date        -- Specific instance date
        FROM registrations r
        JOIN users u ON r.user_id = u.user_id
        JOIN event_instances ei ON r.event_instance_id = ei.event_instance_id
        JOIN master_events me ON ei.master_event_id = me.master_event_id
    `;
    
    if (req.session.user.role === 'admin') {
      // FIX 1: Manager Query - Pulls all records
      result = await pool.query(`
        ${baseQuery}
        ORDER BY r.created_at DESC
      `);
    } else {
      // FIX 2: Regular User Query - Filters by logged-in user's ID
      result = await pool.query(`
        ${baseQuery}
        WHERE r.user_id = $1
        ORDER BY r.created_at DESC
      `, [req.session.user.id]);
    }

    // FIX 3: Ensure the EJS view receives the data under a consistent name (registrations)
    res.render('surveys', { user: req.session.user, surveys: result.rows });
    
  } catch (err) {
    console.error('❌ Error loading registrations/surveys:', err);
    res.status(500).send('Error loading registration and survey data.');
  }
});

// Render form to submit a new survey (User only)
app.get('/survey_new', requireLogin, async (req, res) => {
  try {
    // FIX 4: Query Event Instances to show available events for survey
    const events = await pool.query(`
        SELECT 
            ei.event_instance_id AS event_id, -- Return instance ID as event_id for the form
            me.event_name AS title
        FROM event_instances ei
        JOIN master_events me ON ei.master_event_id = me.master_event_id
        ORDER BY me.event_name
    `);
    res.render('survey_new', { user: req.session.user, events: events.rows });
  } catch (err) {
    console.error('Error loading new survey form:', err);
    res.status(500).send('Error loading survey form.');
  }
});

// Handle survey submission
app.post('/surveys', requireLogin, async (req, res) => {
  // FIX 5: Collect data for the registrations table columns
  const { event_id, satisfaction, usefulness, recommendation, comments } = req.body;
  
  try {
    const user_id = req.session.user.id; 

    // IMPORTANT: The survey data is being updated/inserted into the REGISTRATIONS table.
    // Assuming the user has already registered for the event, we look for that existing registration record.
    
    // Check if a registration record exists for this user and event instance
    const registrationCheck = await pool.query(
      'SELECT registration_id FROM registrations WHERE user_id = $1 AND event_instance_id = $2',
      [user_id, event_id]
    );

    if (registrationCheck.rows.length === 0) {
        // If they haven't registered yet, create a basic record first
         await pool.query(
            'INSERT INTO registrations (user_id, event_instance_id, status) VALUES ($1, $2, $3)',
            [user_id, event_id, 'registered']
        );
    }
    
    // Now, update the registration record with the survey scores
    await pool.query(
      `UPDATE registrations 
       SET survey_satisfaction = $1, 
           survey_usefulness = $2, 
           survey_instructor = $3, 
           survey_recommendation = $4, 
           survey_comments = $5 
       WHERE user_id = $6 AND event_instance_id = $7`,
      [satisfaction, usefulness, satisfaction, recommendation, comments, user_id, event_id]
    );

    res.redirect('/surveys');
  } catch (err) {
    console.error('❌ Error submitting survey:', err);
    res.status(500).send('Error submitting survey.');
  }
});


// ------------------- ERROR HANDLING -------------------
app.use((req, res) => res.status(404).send('Page not found'));
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something went wrong!');
});

// ------------------- START SERVER -------------------
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
});

