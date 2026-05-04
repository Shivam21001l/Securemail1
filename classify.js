/**
 * SecureMail — Smart Inbox Classification Engine
 * Classifies emails automatically based on subject line, sender, and domain.
 * Zero user configuration required beyond creating custom sections.
 */

// ─── Temporary / OTP mail domains ────────────────────────────────
const TEMP_DOMAINS = new Set([
  'mailinator.com','guerrillamail.com','tempmail.com','throwam.com',
  'yopmail.com','maildrop.cc','sharklasers.com','guerrillamail.info',
  'guerrillamail.biz','guerrillamail.de','guerrillamail.net','guerrillamail.org',
  'spam4.me','trashmail.com','trashmail.me','trashmail.net','trashmail.at',
  'dispostable.com','fakeinbox.com','mailnull.com','spamgourmet.com',
  'discard.email','discardmail.com','spamfree24.org','bigstring.com',
  'throwaway.email','getnada.com','mailnesia.com','spamherr.com'
]);

// ─── Social platform domains ──────────────────────────────────────
const SOCIAL_DOMAINS = [
  'linkedin.com','facebook.com','twitter.com','instagram.com',
  'whatsapp.com','snapchat.com','tiktok.com','reddit.com','discord.com',
  'slack.com','github.com','meetup.com','eventbrite.com','pinterest.com',
  'tumblr.com','twitch.tv','youtube.com','telegram.org','signal.org'
];

// ─── Personal mail providers (exclude from "professional" detection) ──
const PERSONAL_PROVIDERS = new Set([
  'gmail.com','yahoo.com','hotmail.com','outlook.com','live.com',
  'icloud.com','protonmail.com','aol.com','mail.com','yandex.com'
]);

// ─── Academic TLD patterns ────────────────────────────────────────
const ACADEMIC_TLDS = ['.edu','.ac.in','.ac.uk','.edu.au','.ac.nz','.edu.sg','.edu.pk'];
const ACADEMIC_KEYWORDS_IN_DOMAIN = ['university','college','school','institute','academy'];

// ─── Subject-line keyword lists ───────────────────────────────────
const KEYWORDS = {

  temporary: [
    'otp','one-time password','one time password','verification code',
    'confirm your email','your code is','security code','login link',
    'magic link','temporary password','reset password','activation link',
    'activate your account','verify your email','email verification',
    'account activation','confirmation code','expires in','expiring soon',
    'access code','auth code','2fa code','two-factor','auth token'
  ],

  spam: [
    'winner','you have won','congratulations you\'ve been selected',
    'claim your prize','act now','limited time offer','unsubscribe',
    'you have been pre-approved','earn money from home','nigerian prince',
    'work from home','make money fast','get rich quick','free gift',
    'no cost','risk free','100% guaranteed','cash prize','lottery',
    'you are selected','unclaimed funds','wire transfer','inheritance',
    'investment opportunity','double your money','earn $','click now',
    'urgent response required','final notice','account suspended',
    '!!!','sale!!!','huge discount','% off today','buy now','order now',
    'special promotion','exclusive deal','you qualify'
  ],

  university: [
    // Exams & results
    'exam','examination','mid-term','midterm','end-term','semester exam',
    'hall ticket','admit card','seat number','revaluation','re-exam',
    'supplementary exam','arrear','backlog','cgpa','sgpa','marksheet',
    'result declared','grade card','grade report','pass','fail',
    // Classes & schedule
    'lecture','class cancelled','class postponed','timetable','schedule',
    'syllabus','attendance','attendance shortage','attendance warning',
    'lab session','practical exam','viva','tutorial','workshop',
    // Assignments & projects
    'assignment','assignment due','submission deadline','project report',
    'project submission','thesis','dissertation','coursework','internship report',
    // Admin
    'semester','semester fees','hostel','hostel allotment','scholarship',
    'fee reminder','library fine','admission','registration','enrollment',
    'course registration','subject registration','drop course','add course',
    'academic calendar','convocation','graduation','commencement',
    'dean','hod','principal','registrar','faculty','professor',
    'department of','academic','college','university','campus',
    'placement','campus drive','internship offer'
  ],

  professional: [
    // Finance / Legal
    'invoice','invoice attached','payment due','quotation','purchase order',
    'po number','nda','contract','agreement','terms and conditions',
    'legal notice','compliance','audit',
    // Project / Work
    'project update','status update','deliverable','milestone','sprint',
    'standup','retrospective','action required','follow up','follow-up',
    'deadline','due date','please find attached','kind regards',
    'best regards','as per our discussion','per our conversation',
    'meeting invite','calendar invite','conference call','zoom meeting',
    'teams meeting','google meet','your attendance is required',
    // HR / Onboarding
    'offer letter','joining date','onboarding','employee','payslip','salary',
    'appraisal','performance review','leave approval','expense report',
    // Dev / Tech
    'pull request','pr review','code review','deployment','release notes',
    'jira','asana','trello','ticket assigned','bug report','incident',
    // Sales / Business
    'proposal','rfp','rfi','client update','vendor','partnership',
    'business opportunity','quarterly report','annual report','board meeting'
  ],

  social: [
    'connected with you','sent you a message','commented on your',
    'liked your post','reacted to','tagged you','mentioned you',
    'friend request','follow request','new follower','started following',
    'invited you to','birthday','happy birthday','party invitation',
    'hangout','reunion','get together','rsvp','event invitation',
    'join the group','group invite','you\'ve been added','new message from',
    'someone viewed your profile','profile visit','endorsement'
  ]
};

// ─── University sub-tag map ───────────────────────────────────────
const UNI_SUBTAGS = {
  'LEAVE':     ['leave','permission','absent','sick leave','casual leave','medical leave','half day','late arrival'],
  'RESULTS':   ['result','grade','cgpa','sgpa','marksheet','marks','pass','fail','declared'],
  'FEES':      ['fee','dues','payment','challan','fine','library fine','hostel fee'],
  'EXAMS':     ['exam','hall ticket','admit card','timetable','schedule','seat number','mid-term','end-term'],
  'PLACEMENT': ['placement','internship','offer letter','campus drive','recruitment','interview','shortlisted'],
  'ASSIGN':    ['assignment','submission','project','report','due','deadline'],
};

// ─── System section definitions (3 permanent, non-deletable) ─────
export const SYSTEM_SECTIONS = [
  { id:'primary', label:'Primary', color:'#00c8ff', colorVar:'var(--cyan)',  badgeLabel:null,   badgeBg:'var(--cyan-dim)' },
  { id:'spam',    label:'Spam',    color:'#ff4060', colorVar:'var(--red)',   badgeLabel:'SPAM', badgeBg:'var(--red-dim)' },
  { id:'social',  label:'Social',  color:'#ffb700', colorVar:'var(--amber)', badgeLabel:'SOC',  badgeBg:'var(--amber-dim)' },
];

// ─── Preset templates — offered in the "New Section" modal ────────
// These are just starting points: user picks one → form is pre-filled
export const PRESET_TEMPLATES = [
  {
    name: 'University',
    color: '#a855f7',
    icon: 'graduation-cap',
    keywords: ['exam','assignment','attendance','cgpa','result','timetable','semester',
               'hostel','scholarship','lecture','hall ticket','backlog','fee','placement',
               'internship','admit card','syllabus','dissertation'],
    senders: ['.edu', '.ac.in', '.ac.uk', '.edu.au']
  },
  {
    name: 'Work',
    color: '#00ff88',
    icon: 'briefcase',
    keywords: ['invoice','meeting','deadline','project','sprint','standup','client',
               'deliverable','nda','contract','proposal','offer letter','onboarding',
               'payslip','appraisal','pull request','deployment','jira'],
    senders: []
  },
  {
    name: 'Banking',
    color: '#ffb700',
    icon: 'landmark',
    keywords: ['transaction','debit','credit','statement','otp','account','balance',
               'transfer','emi','bank','loan','upi','payment confirmed','your account',
               'net banking','card ending','atm','neft','rtgs','imps'],
    senders: []
  },
  {
    name: 'Shopping',
    color: '#f97316',
    icon: 'shopping-bag',
    keywords: ['order confirmed','shipped','out for delivery','delivered','track your order',
               'invoice attached','return','refund','your order','dispatch','amazon',
               'flipkart','myntra','swiggy','zomato','meesho'],
    senders: ['amazon.', 'flipkart.', 'myntra.', 'noreply@']
  },
  {
    name: 'Newsletters',
    color: '#14b8a6',
    icon: 'newspaper',
    keywords: ['newsletter','weekly digest','monthly update','unsubscribe','issue #',
               'read more','this week in','top stories','curated','edition'],
    senders: []
  },
  {
    name: 'Travel',
    color: '#ec4899',
    icon: 'plane',
    keywords: ['booking confirmed','flight','hotel','check-in','itinerary','pnr',
               'boarding pass','visa','reservation','ticket','cab booking'],
    senders: ['makemytrip.', 'irctc.', 'goibibo.', 'airbnb.']
  },
];


// ─── Main classification function ─────────────────────────────────
/**
 * Classify an email automatically based on subject + sender.
 * @param {{from:string, subject:string}} email
 * @param {Array}  customSections  - user-defined sections from localStorage
 * @param {Object} senderRules     - {email|domain: sectionId}
 * @returns {{ section:string, confidence:number, subTag:string|null }}
 */
export function classifyEmail(email, customSections = [], senderRules = {}) {
  const subject = (email.subject || '').toLowerCase();
  const from    = (email.from    || '').toLowerCase();
  const domain  = extractDomain(from);

  // ── PRIORITY 0: User-defined sender rules (always wins) ───────
  if (senderRules[from])   return { section: senderRules[from],   confidence: 100, subTag: null };
  if (domain && senderRules[domain]) return { section: senderRules[domain], confidence: 100, subTag: null };

  // ── PRIORITY 1: Custom user sections (highest priority after rules) ─
  for (const sec of customSections) {
    const senders = (sec.senders  || []).map(s => s.toLowerCase());
    const kws     = (sec.keywords || []).map(k => k.toLowerCase());
    // Sender domain/address match
    if (senders.some(s => from.includes(s) || domain.includes(s))) {
      return { section: sec.id, confidence: 95, subTag: null };
    }
    // Keyword match in subject
    if (kws.length > 0 && kws.some(kw => subject.includes(kw))) {
      return { section: sec.id, confidence: 85, subTag: null };
    }
  }

  // ── PRIORITY 2: Spam ─────────────────────────────────────────
  const spamScore =
    (matchAny(subject, KEYWORDS.spam) ? 50 : 0) +
    (exclCount(subject) > 3           ? 20 : 0) +
    (upperRatio(subject) > 0.45       ? 20 : 0);
  if (spamScore >= 50) {
    return { section: 'spam', confidence: Math.min(95, 50 + spamScore), subTag: null };
  }

  // ── PRIORITY 3: Social ────────────────────────────────────────
  const isSocialDomain = SOCIAL_DOMAINS.some(d => domain.includes(d));
  if (isSocialDomain || matchAny(subject, KEYWORDS.social)) {
    return { section: 'social', confidence: 88, subTag: null };
  }

  // ── Default: Primary (catches everything else) ────────────────
  return { section: 'primary', confidence: 60, subTag: null };
}

// ─── Helpers ─────────────────────────────────────────────────────
function extractDomain(email) {
  const m = email.match(/@([^>@\s]+)/);
  return m ? m[1].toLowerCase() : '';
}

function matchAny(text, keywords) {
  return keywords.some(kw => text.includes(kw));
}

function exclCount(str) {
  return (str.match(/!/g) || []).length;
}

function upperRatio(str) {
  if (!str || str.length < 4) return 0;
  const upper = (str.match(/[A-Z]/g) || []).length;
  return upper / str.length;
}

function isAcademicDomain(domain) {
  if (!domain) return false;
  if (ACADEMIC_TLDS.some(tld => domain.endsWith(tld))) return true;
  if (ACADEMIC_KEYWORDS_IN_DOMAIN.some(kw => domain.includes(kw))) return true;
  return false;
}

function detectUniSubTag(subject) {
  for (const [tag, kws] of Object.entries(UNI_SUBTAGS)) {
    if (kws.some(kw => subject.includes(kw))) return tag;
  }
  return null;
}

// ─── Section color lookup ─────────────────────────────────────────
export function getSectionInfo(sectionId, customSections = []) {
  const sys = SYSTEM_SECTIONS.find(s => s.id === sectionId);
  if (sys) return sys;
  const cust = customSections.find(s => s.id === sectionId);
  if (cust) return {
    id: cust.id, label: cust.name,
    color: cust.color, colorVar: cust.color,
    badgeLabel: cust.name.slice(0,6).toUpperCase(),
    badgeBg: hexToRgba(cust.color, 0.12)
  };
  return SYSTEM_SECTIONS[0]; // fallback to primary
}

function hexToRgba(hex, a) {
  const r = parseInt(hex.slice(1,3),16);
  const g = parseInt(hex.slice(3,5),16);
  const b = parseInt(hex.slice(5,7),16);
  return `rgba(${r},${g},${b},${a})`;
}

// ─── Unread count helper ──────────────────────────────────────────
export function countUnreadInSection(emails, sectionId, customSections, senderRules) {
  return emails.filter(e => {
    const r = classifyEmail(e, customSections, senderRules);
    return r.section === sectionId && !e.read;
  }).length;
}

// ─── Role presets ─────────────────────────────────────────────────
export function getRolePresets(role) {
  const PRESETS = {
    teacher: [
      { name:'Leave Applications', icon:'calendar',      color:'#ffb700',
        keywords:['leave','permission','absent','sick leave','casual leave','medical leave','half day','late arrival','early departure'] },
      { name:'Student Queries',    icon:'message-square',color:'#a855f7',
        keywords:['doubt','query','question','clarification','help needed','explain','need guidance'] },
      { name:'Exam & Results',     icon:'file-check',    color:'#00c8ff',
        keywords:['exam','marks','grade','result','revaluation','answer sheet','oral exam','viva'] },
      { name:'University Notices', icon:'bell',          color:'#00ff88',
        keywords:['circular','notice','announcement','mandatory','all staff','all faculty','notice board'] },
      { name:'Parent Comms',       icon:'users',         color:'#f97316',
        keywords:['parent','guardian','mother','father','regarding my ward','my child','ward'] },
    ],
    student: [
      { name:'Lectures & Classes', icon:'clock',         color:'#00c8ff',
        keywords:['class','lecture','schedule','timetable','postponed','cancelled','venue','lab'] },
      { name:'Assignments',        icon:'file-check',    color:'#a855f7',
        keywords:['assignment','submission','deadline','due date','submit by','project','report'] },
      { name:'Results & Grades',   icon:'trophy',        color:'#00ff88',
        keywords:['result','grade','cgpa','sgpa','marksheet','passed','failed','backlog','arrear'] },
      { name:'Placement',          icon:'briefcase',     color:'#ffb700',
        keywords:['placement','internship','offer letter','campus drive','recruitment','interview','shortlisted'] },
      { name:'Fee Reminders',      icon:'tag',           color:'#ff4060',
        keywords:['fee','dues','pay by','challan','last date','fine','hostel fee'] },
    ],
    professional: [
      { name:'Invoices & Finance', icon:'tag',           color:'#00ff88',
        keywords:['invoice','payment due','quotation','purchase order','receipt','billing'] },
      { name:'Meetings',           icon:'calendar',      color:'#00c8ff',
        keywords:['meeting','calendar invite','zoom','teams meeting','conference','standup'] },
      { name:'Projects',           icon:'briefcase',     color:'#a855f7',
        keywords:['project','sprint','milestone','deliverable','deadline','status update'] },
    ],
  };
  return PRESETS[role] || [];
}

// ─── localStorage persistence ─────────────────────────────────────
export function loadCustomSections() {
  try { return JSON.parse(localStorage.getItem('sm_custom_sections') || '[]'); }
  catch { return []; }
}
export function saveCustomSections(sections) {
  localStorage.setItem('sm_custom_sections', JSON.stringify(sections));
}

export function loadSenderRules() {
  try { return JSON.parse(localStorage.getItem('sm_sender_rules') || '{}'); }
  catch { return {}; }
}
export function saveSenderRules(rules) {
  localStorage.setItem('sm_sender_rules', JSON.stringify(rules));
}

export function loadUserRole() {
  return localStorage.getItem('sm_user_role') || null;
}
export function saveUserRole(role) {
  localStorage.setItem('sm_user_role', role);
}

export function loadManualOverrides() {
  try { return JSON.parse(localStorage.getItem('sm_overrides') || '{}'); }
  catch { return {}; }
}
export function saveManualOverrides(overrides) {
  localStorage.setItem('sm_overrides', JSON.stringify(overrides));
}
