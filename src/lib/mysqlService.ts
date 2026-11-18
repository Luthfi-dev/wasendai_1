import mysql from 'mysql2/promise';
import {
  WhatsAppMessageLog,
  AutoReplyRule,
  WhatsAppSession,
  UserAccount,
  GeminiApiKey
} from '../types/whatsapp.js';
import { decryptData, encryptData } from './security.js';
import { initDbFile } from './db.js';

let pool: mysql.Pool | null = null;
let currentPoolSignature = '';

export interface MysqlConfigOverride {
  host?: string;
  port?: number;
  user?: string;
  password?: string;
  database?: string;
  ssl?: boolean;
}

export function getEffectiveMysqlConfig(configOverride?: MysqlConfigOverride) {
  const pickNonEmpty = (overrideVal?: string, envVal?: string, savedVal?: string) => {
    if (typeof overrideVal === 'string' && overrideVal.trim() !== '') {
      return overrideVal.trim();
    }
    if (typeof envVal === 'string' && envVal.trim() !== '') {
      return envVal.trim();
    }
    return (savedVal || '').trim();
  };

  // Prioritize explicit override, then server environment variables (Hosting / AI Studio Secrets), then saved sysConfig fallback
  const hasAllEnv = Boolean(
    process.env.MYSQL_HOST?.trim() &&
    process.env.MYSQL_USER?.trim() &&
    process.env.MYSQL_DATABASE?.trim()
  );
  const sysConfig = hasAllEnv ? null : initDbFile().systemConfig;

  const host = pickNonEmpty(configOverride?.host, process.env.MYSQL_HOST, sysConfig?.mysql_host);
  const port = Number(configOverride?.port || process.env.MYSQL_PORT || sysConfig?.mysql_port || 3306) || 3306;
  const user = pickNonEmpty(configOverride?.user, process.env.MYSQL_USER, sysConfig?.mysql_user);

  const overridePass = typeof configOverride?.password === 'string' && !configOverride.password.includes('****')
    ? configOverride.password
    : '';
  const rawPass = overridePass !== ''
    ? overridePass
    : (process.env.MYSQL_PASSWORD || sysConfig?.mysql_password || '');
  const password = decryptData(rawPass);
  const database = pickNonEmpty(configOverride?.database, process.env.MYSQL_DATABASE, sysConfig?.mysql_database);

  const envSslRaw = (process.env.MYSQL_SSL || '').trim().toLowerCase();
  const envSsl = envSslRaw === 'true' || envSslRaw === '1' || envSslRaw === 'yes';
  const ssl = configOverride?.ssl !== undefined
    ? Boolean(configOverride.ssl)
    : envSsl;

  return { host, port, user, password, database, ssl };
}

function formatMysqlErrorDiagnostic(
  err: any,
  cfg: { host: string; port: number; user: string; database: string; ssl: boolean }
): {
  code: string;
  detail: string;
  hint: string;
} {
  const collectedCodes: string[] = [];
  const collectedMessages: string[] = [];

  const inspectErr = (e: any, depth = 0) => {
    if (!e || depth > 4) return;
    if (typeof e.code === 'string' && e.code.trim()) {
      collectedCodes.push(e.code.trim());
    }
    if (typeof e.sqlMessage === 'string' && e.sqlMessage.trim()) {
      collectedMessages.push(e.sqlMessage.trim());
    } else if (typeof e.message === 'string' && e.message.trim()) {
      collectedMessages.push(e.message.trim());
    }
    if (Array.isArray(e.errors)) {
      for (const sub of e.errors) {
        inspectErr(sub, depth + 1);
      }
    }
  };

  inspectErr(err);

  const uniqueCodes = Array.from(new Set(collectedCodes));
  const uniqueMessages = Array.from(new Set(collectedMessages));
  const primaryCode = uniqueCodes[0] || (typeof err?.errno === 'number' ? `ERRNO_${err.errno}` : 'MYSQL_CONNECTION_ERROR');
  const rawDetail = uniqueMessages.join(' | ') || `Gagal terhubung ke ${cfg.host}:${cfg.port}`;

  let hint = `Periksa kembali Host (${cfg.host}), Port (${cfg.port}), User (${cfg.user}), Password, dan Nama Database (${cfg.database}).`;

  if (primaryCode === 'ECONNREFUSED') {
    if (cfg.host === 'localhost' || cfg.host === '127.0.0.1' || cfg.host === '::1') {
      hint = `Tidak ada layanan MySQL yang berjalan di ${cfg.host}:${cfg.port} di dalam server/container ini. Jika database berada di cPanel/VPS/Cloud eksternal, isi Host dengan IP publik atau domain server database Anda (bukan localhost).`;
    } else {
      hint = `Server ${cfg.host}:${cfg.port} menolak koneksi TCP. Pastikan service MySQL/MariaDB aktif, port ${cfg.port} terbuka di firewall, dan MySQL mendengarkan koneksi remote (bind-address = 0.0.0.0).`;
    }
  } else if (primaryCode === 'ETIMEDOUT' || primaryCode === 'ENETUNREACH' || primaryCode === 'EHOSTUNREACH') {
    hint = `Koneksi ke ${cfg.host}:${cfg.port} habis waktu (timeout) atau jaringan tidak terjangkau. Pada cPanel/VPS, pastikan port ${cfg.port} tidak diblokir firewall dan IP server aplikasi sudah ditambahkan di Remote MySQL / IP Whitelist.`;
  } else if (primaryCode === 'ENOTFOUND' || primaryCode === 'EAI_AGAIN') {
    hint = `Nama host "${cfg.host}" tidak ditemukan oleh DNS. Periksa penulisan domain/hostname atau gunakan alamat IP server database yang valid.`;
  } else if (primaryCode === 'ER_ACCESS_DENIED_ERROR' || primaryCode === 'ER_DBACCESS_DENIED_ERROR') {
    hint = `Username "${cfg.user}" atau password ditolak oleh MySQL, atau user belum diberi izin akses remote (@'%' / hostname) serta hak akses ke database "${cfg.database}".`;
  } else if (primaryCode === 'ER_BAD_DB_ERROR') {
    hint = `Koneksi ke server berhasil, namun database "${cfg.database}" belum ada. Buat database tersebut terlebih dahulu di cPanel / phpMyAdmin / MySQL.`;
  } else if (
    primaryCode.includes('SSL') ||
    rawDetail.toLowerCase().includes('ssl') ||
    rawDetail.toLowerCase().includes('tls') ||
    rawDetail.toLowerCase().includes('secure transport')
  ) {
    hint = cfg.ssl
      ? `Handshake SSL/TLS gagal dengan ${cfg.host}:${cfg.port}. Periksa apakah server MySQL mendukung SSL atau set MYSQL_SSL_REJECT_UNAUTHORIZED=false jika menggunakan sertifikat self-signed.`
      : `Server MySQL Anda mewajibkan koneksi terenkripsi SSL/TLS. Aktifkan opsi SSL/TLS (atau set MYSQL_SSL=true di environment server).`;
  } else if (primaryCode === 'ER_NOT_SUPPORTED_AUTH_MODE') {
    hint = `Metode autentikasi MySQL tidak didukung atau memerlukan SSL aktif. Coba aktifkan SSL atau ubah plugin auth user MySQL ke mysql_native_password / caching_sha2_password.`;
  }

  return {
    code: primaryCode,
    detail: rawDetail,
    hint
  };
}

export function isMysqlConfigured(configOverride?: MysqlConfigOverride): boolean {
  const cfg = getEffectiveMysqlConfig(configOverride);
  return Boolean(cfg.host && cfg.user && cfg.database);
}

/**
 * Returns an active connection pool using environment / systemConfig settings.
 * Returns null cleanly when MySQL is not configured (local-only mode).
 */
export function getMysqlPool(configOverride?: MysqlConfigOverride): mysql.Pool | null {
  const cfg = getEffectiveMysqlConfig(configOverride);
  if (!cfg.host || !cfg.user || !cfg.database) {
    return null;
  }

  const sig = `${cfg.host}:${cfg.port}:${cfg.user}:${cfg.database}:${cfg.password.length}:${cfg.ssl ? 'ssl' : 'plain'}`;
  if (pool && currentPoolSignature === sig) {
    return pool;
  }

  if (pool && currentPoolSignature !== sig) {
    pool.end().catch(() => {});
    pool = null;
  }

  currentPoolSignature = sig;
  const poolLimit = Math.min(20, Math.max(2, Number(process.env.MYSQL_POOL_LIMIT) || 6));
  const poolOptions: mysql.PoolOptions = {
    host: cfg.host,
    port: cfg.port,
    user: cfg.user,
    password: cfg.password,
    database: cfg.database,
    waitForConnections: true,
    connectionLimit: poolLimit,
    maxIdle: Math.min(3, poolLimit),
    idleTimeout: 60000,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 10000,
    connectTimeout: 8000
  };

  if (cfg.ssl) {
    poolOptions.ssl = {
      rejectUnauthorized: process.env.MYSQL_SSL_REJECT_UNAUTHORIZED !== 'false'
    };
  }

  pool = mysql.createPool(poolOptions);
  return pool;
}

export async function closeMysqlPool(): Promise<void> {
  if (!pool) return;
  const active = pool;
  pool = null;
  currentPoolSignature = '';
  try {
    await active.end();
  } catch {
    // Ignore close errors during shutdown
  }
}

let isSchemaInitialized = false;
let lastSchemaInitError: { code: string; detail: string; hint: string } | null = null;

interface DetectedSchemaMeta {
  kvKeyCol: 'kv_key' | 'setting_key';
  kvValCol: 'kv_value' | 'setting_value';
  smtpUserCol: 'user_email' | 'user';
  smtpPassCol: 'pass_encrypted' | 'pass';
  smtpHasLastError: boolean;
  geminiKeyCol: 'key_encrypted' | 'api_key';
  hasWhatsappMessagesTable: boolean;
  sessionsHasAiEnabled: boolean;
  sessionsHasCustomPrompt: boolean;
  sessionsHasConnectedAt: boolean;
  sessionsHasLastActivityAt: boolean;
  sessionsHasTotalMessagesCount: boolean;
  usersHasTotalMessagesCount: boolean;
}

let detectedSchemaMeta: DetectedSchemaMeta = {
  kvKeyCol: 'kv_key',
  kvValCol: 'kv_value',
  smtpUserCol: 'user_email',
  smtpPassCol: 'pass_encrypted',
  smtpHasLastError: true,
  geminiKeyCol: 'key_encrypted',
  hasWhatsappMessagesTable: false,
  sessionsHasAiEnabled: false,
  sessionsHasCustomPrompt: false,
  sessionsHasConnectedAt: false,
  sessionsHasLastActivityAt: false,
  sessionsHasTotalMessagesCount: false,
  usersHasTotalMessagesCount: false
};

function toMysqlDateTime(value?: string | Date | null, allowNull = true): string | null {
  if (!value) {
    return allowNull ? null : new Date().toISOString().slice(0, 19).replace('T', ' ');
  }
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) {
    return allowNull ? null : new Date().toISOString().slice(0, 19).replace('T', ' ');
  }
  return d.toISOString().slice(0, 19).replace('T', ' ');
}

function fromMysqlDateTime(value: any): string {
  if (!value) return '';
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? '' : value.toISOString();
  }
  return String(value);
}

async function detectSchemaMeta(conn: mysql.PoolConnection): Promise<void> {
  try {
    const [kvCols] = await conn.query<mysql.RowDataPacket[]>(`SHOW COLUMNS FROM app_kv_store`);
    const kvFields = new Set(kvCols.map(c => String(c.Field)));
    detectedSchemaMeta.kvKeyCol = kvFields.has('kv_key')
      ? 'kv_key'
      : kvFields.has('setting_key')
        ? 'setting_key'
        : 'kv_key';
    detectedSchemaMeta.kvValCol = kvFields.has('kv_value')
      ? 'kv_value'
      : kvFields.has('setting_value')
        ? 'setting_value'
        : 'kv_value';
  } catch {
    // Keep defaults
  }

  try {
    const [smtpCols] = await conn.query<mysql.RowDataPacket[]>(`SHOW COLUMNS FROM smtp_accounts`);
    const smtpFields = new Set(smtpCols.map(c => String(c.Field)));
    detectedSchemaMeta.smtpUserCol = smtpFields.has('user_email')
      ? 'user_email'
      : smtpFields.has('user')
        ? 'user'
        : 'user_email';
    detectedSchemaMeta.smtpPassCol = smtpFields.has('pass_encrypted')
      ? 'pass_encrypted'
      : smtpFields.has('pass')
        ? 'pass'
        : 'pass_encrypted';
    detectedSchemaMeta.smtpHasLastError = smtpFields.has('last_error');
  } catch {
    // Keep defaults
  }

  try {
    const [gemCols] = await conn.query<mysql.RowDataPacket[]>(`SHOW COLUMNS FROM gemini_keys`);
    const gemFields = new Set(gemCols.map(c => String(c.Field)));
    detectedSchemaMeta.geminiKeyCol = gemFields.has('key_encrypted')
      ? 'key_encrypted'
      : gemFields.has('api_key')
        ? 'api_key'
        : 'key_encrypted';
  } catch {
    // Keep defaults
  }

  try {
    const [waMsgTbl] = await conn.query<mysql.RowDataPacket[]>(`SHOW TABLES LIKE 'whatsapp_messages'`);
    detectedSchemaMeta.hasWhatsappMessagesTable = Array.isArray(waMsgTbl) && waMsgTbl.length > 0;
  } catch {
    detectedSchemaMeta.hasWhatsappMessagesTable = false;
  }

  try {
    const [sessCols] = await conn.query<mysql.RowDataPacket[]>(`SHOW COLUMNS FROM whatsapp_sessions`);
    const sessFields = new Set(sessCols.map(c => String(c.Field)));
    detectedSchemaMeta.sessionsHasAiEnabled = sessFields.has('ai_enabled');
    detectedSchemaMeta.sessionsHasCustomPrompt = sessFields.has('custom_system_prompt');
    detectedSchemaMeta.sessionsHasConnectedAt = sessFields.has('connected_at');
    detectedSchemaMeta.sessionsHasLastActivityAt = sessFields.has('last_activity_at');
    detectedSchemaMeta.sessionsHasTotalMessagesCount = sessFields.has('total_messages_count');
  } catch {
    detectedSchemaMeta.sessionsHasAiEnabled = false;
    detectedSchemaMeta.sessionsHasCustomPrompt = false;
    detectedSchemaMeta.sessionsHasConnectedAt = false;
    detectedSchemaMeta.sessionsHasLastActivityAt = false;
    detectedSchemaMeta.sessionsHasTotalMessagesCount = false;
  }

  try {
    const [userCols] = await conn.query<mysql.RowDataPacket[]>(`SHOW COLUMNS FROM app_users`);
    const userFields = new Set(userCols.map(c => String(c.Field)));
    detectedSchemaMeta.usersHasTotalMessagesCount = userFields.has('total_messages_count');
  } catch {
    detectedSchemaMeta.usersHasTotalMessagesCount = false;
  }
}

/**
 * Automatically creates required MySQL tables on startup if MySQL is configured.
 */
export async function initMysqlSchemaIfNotExists(configOverride?: MysqlConfigOverride): Promise<boolean> {
  if (!isMysqlConfigured(configOverride)) return false;
  if (isSchemaInitialized && !configOverride) return true;

  const cfg = getEffectiveMysqlConfig(configOverride);
  try {
    const p = getMysqlPool(configOverride);
    if (!p) return false;
    const conn = await p.getConnection();
    lastSchemaInitError = null;
    try {
      await conn.query(`
        CREATE TABLE IF NOT EXISTS message_logs (
          id VARCHAR(120) PRIMARY KEY,
          user_id VARCHAR(100),
          session_id VARCHAR(100),
          sender_phone VARCHAR(50),
          sender_name VARCHAR(150),
          message_body TEXT,
          reply_body TEXT,
          direction VARCHAR(30),
          status VARCHAR(30),
          ai_generated TINYINT(1) DEFAULT 0,
          matched_rule_id VARCHAR(100),
          created_at VARCHAR(50)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
      `);

      await conn.query(`ALTER TABLE message_logs ADD COLUMN user_id VARCHAR(100)`).catch(() => {});
      await conn.query(`ALTER TABLE message_logs ADD COLUMN session_id VARCHAR(100)`).catch(() => {});

      await conn.query(`
        CREATE TABLE IF NOT EXISTS whatsapp_sessions (
          id VARCHAR(120) PRIMARY KEY,
          user_id VARCHAR(100),
          session_name VARCHAR(150),
          phone_number VARCHAR(50),
          phone_number_id VARCHAR(100),
          access_token TEXT,
          auth_method VARCHAR(50),
          status VARCHAR(50),
          is_primary TINYINT(1) DEFAULT 0,
          ai_enabled TINYINT(1) NULL DEFAULT NULL,
          custom_system_prompt TEXT NULL,
          connected_at VARCHAR(50),
          last_activity_at VARCHAR(50),
          total_messages_count INT DEFAULT 0,
          expires_at VARCHAR(50),
          created_at VARCHAR(50),
          updated_at VARCHAR(50)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
      `);

      await conn.query(`ALTER TABLE whatsapp_sessions ADD COLUMN user_id VARCHAR(100)`).catch(() => {});
      await conn.query(`ALTER TABLE whatsapp_sessions ADD COLUMN connected_at VARCHAR(50)`).catch(() => {});
      await conn.query(`ALTER TABLE whatsapp_sessions ADD COLUMN last_activity_at VARCHAR(50)`).catch(() => {});
      await conn.query(`ALTER TABLE whatsapp_sessions ADD COLUMN total_messages_count INT DEFAULT 0`).catch(() => {});
      await conn.query(`ALTER TABLE whatsapp_sessions ADD COLUMN expires_at VARCHAR(50)`).catch(() => {});
      await conn.query(`ALTER TABLE whatsapp_sessions ADD COLUMN ai_enabled TINYINT(1) NULL DEFAULT NULL`).catch(() => {});
      await conn.query(`ALTER TABLE whatsapp_sessions ADD COLUMN custom_system_prompt TEXT NULL`).catch(() => {});

      await conn.query(`
        CREATE TABLE IF NOT EXISTS app_users (
          id VARCHAR(120) PRIMARY KEY,
          username VARCHAR(100) UNIQUE,
          name VARCHAR(150),
          role VARCHAR(30),
          email VARCHAR(150),
          phone VARCHAR(50),
          password TEXT,
          is_active TINYINT(1) DEFAULT 0,
          email_verified TINYINT(1) DEFAULT 0,
          wa_verified TINYINT(1) DEFAULT 0,
          verification_otp VARCHAR(20),
          otp_expires_at VARCHAR(50),
          plan_id VARCHAR(50),
          plan_status VARCHAR(50),
          payment_note TEXT,
          payment_receipt_url TEXT,
          requested_plan_id VARCHAR(50),
          ai_verified TINYINT(1) DEFAULT 0,
          ai_verification_notes TEXT,
          ai_verified_at VARCHAR(50),
          security_pin TEXT,
          pin_failed_attempts INT DEFAULT 0,
          is_bot_locked TINYINT(1) DEFAULT 0,
          api_key VARCHAR(150),
          custom_gemini_key TEXT,
          auto_reply_enabled TINYINT(1) DEFAULT 0,
          auto_reply_activated_at VARCHAR(50),
          ai_enabled TINYINT(1) DEFAULT 0,
          meta_ai_verified TINYINT(1) DEFAULT 0,
          meta_ai_verified_phone VARCHAR(32),
          meta_ai_verified_phones TEXT,
          meta_ai_verified_at VARCHAR(50),
          custom_system_prompt TEXT,
          default_cs_reply_enabled TINYINT(1) DEFAULT 0,
          default_cs_reply_text TEXT,
          allowed_numbers LONGTEXT,
          max_sessions INT DEFAULT 1,
          daily_messages_sent INT DEFAULT 0,
          monthly_messages_sent INT DEFAULT 0,
          daily_ai_sent INT DEFAULT 0,
          monthly_ai_sent INT DEFAULT 0,
          total_messages_count INT DEFAULT 0,
          last_quota_reset_date VARCHAR(20),
          last_quota_reset_month VARCHAR(20),
          last_login_device VARCHAR(150),
          approved_at VARCHAR(50),
          created_at VARCHAR(50)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
      `);

      const alterQueries = [
        `ALTER TABLE app_users ADD COLUMN custom_gemini_key TEXT`,
        `ALTER TABLE app_users ADD COLUMN auto_reply_enabled TINYINT(1) DEFAULT 0`,
        `ALTER TABLE app_users ADD COLUMN auto_reply_activated_at VARCHAR(50)`,
        `ALTER TABLE app_users ADD COLUMN ai_enabled TINYINT(1) DEFAULT 0`,
        `ALTER TABLE app_users ADD COLUMN meta_ai_verified TINYINT(1) DEFAULT 0`,
        `ALTER TABLE app_users ADD COLUMN meta_ai_verified_phone VARCHAR(32)`,
        `ALTER TABLE app_users ADD COLUMN meta_ai_verified_phones TEXT`,
        `ALTER TABLE app_users ADD COLUMN meta_ai_verified_at VARCHAR(50)`,
        `ALTER TABLE app_users ADD COLUMN custom_system_prompt TEXT`,
        `ALTER TABLE app_users ADD COLUMN default_cs_reply_enabled TINYINT(1) DEFAULT 0`,
        `ALTER TABLE app_users ADD COLUMN default_cs_reply_text TEXT`,
        `ALTER TABLE app_users ADD COLUMN allowed_numbers LONGTEXT`,
        `ALTER TABLE app_users ADD COLUMN last_login_device VARCHAR(150)`,
        `ALTER TABLE app_users ADD COLUMN approved_at VARCHAR(50)`,
        `ALTER TABLE app_users ADD COLUMN monthly_messages_sent INT DEFAULT 0`,
        `ALTER TABLE app_users ADD COLUMN daily_ai_sent INT DEFAULT 0`,
        `ALTER TABLE app_users ADD COLUMN monthly_ai_sent INT DEFAULT 0`,
        `ALTER TABLE app_users ADD COLUMN total_messages_count INT DEFAULT 0`,
        `ALTER TABLE app_users ADD COLUMN last_quota_reset_month VARCHAR(20)`,
        `ALTER TABLE app_users ADD COLUMN custom_offline_message TEXT`
      ];
      for (const q of alterQueries) {
        await conn.query(q).catch(() => {});
      }

      await conn.query(`
        CREATE TABLE IF NOT EXISTS auto_reply_rules (
          id VARCHAR(120) PRIMARY KEY,
          user_id VARCHAR(100),
          keyword VARCHAR(255),
          match_type VARCHAR(30),
          response_text TEXT,
          is_active TINYINT(1) DEFAULT 1,
          created_at VARCHAR(50),
          updated_at VARCHAR(50)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
      `);

      await conn.query(`ALTER TABLE auto_reply_rules ADD COLUMN user_id VARCHAR(100)`).catch(() => {});

      await conn.query(`
        CREATE TABLE IF NOT EXISTS smtp_accounts (
          id VARCHAR(120) PRIMARY KEY,
          name VARCHAR(150),
          host VARCHAR(150),
          port INT,
          secure TINYINT(1),
          user_email VARCHAR(150),
          pass_encrypted TEXT,
          sender_name VARCHAR(150),
          is_active TINYINT(1) DEFAULT 1,
          success_count INT DEFAULT 0,
          error_count INT DEFAULT 0,
          last_error TEXT,
          last_used_at VARCHAR(50),
          created_at VARCHAR(50)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
      `);
      await conn.query(`ALTER TABLE smtp_accounts ADD COLUMN last_error TEXT`).catch(() => {});

      await conn.query(`
        CREATE TABLE IF NOT EXISTS gemini_keys (
          id VARCHAR(120) PRIMARY KEY,
          name VARCHAR(150),
          key_encrypted TEXT,
          is_active TINYINT(1) DEFAULT 1,
          usage_count INT DEFAULT 0,
          error_count INT DEFAULT 0,
          last_used_at VARCHAR(50),
          created_at VARCHAR(50)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
      `);

      await conn.query(`
        CREATE TABLE IF NOT EXISTS app_kv_store (
          kv_key VARCHAR(120) PRIMARY KEY,
          kv_value LONGTEXT,
          updated_at VARCHAR(50)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
      `);

      await detectSchemaMeta(conn);

      // Cleanup message logs older than 7 days
      const sevenDaysAgoIso = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
      await conn.query(`DELETE FROM message_logs WHERE created_at < ?`, [sevenDaysAgoIso]).catch(() => {});

      isSchemaInitialized = true;
      return true;
    } finally {
      conn.release();
    }
  } catch (err: any) {
    const diag = formatMysqlErrorDiagnostic(err, cfg);
    lastSchemaInitError = diag;
    console.warn(`[MySQL Schema Init] Fallback to local mode (${diag.code}): ${diag.detail}`);
    return false;
  }
}

export async function purgeOldMysqlLogs(): Promise<void> {
  if (!isMysqlConfigured()) return;
  try {
    const p = getMysqlPool();
    if (!p) return;
    const sevenDaysAgoIso = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    await p.query(`DELETE FROM message_logs WHERE created_at < ?`, [sevenDaysAgoIso]);
  } catch {
    // Non-fatal
  }
}

export async function pushMessageToMysql(m: WhatsAppMessageLog): Promise<void> {
  if (!isMysqlConfigured()) return;
  try {
    const ok = await initMysqlSchemaIfNotExists();
    if (!ok) return;
    const p = getMysqlPool();
    if (!p) return;
    await p.query(
      `INSERT INTO message_logs (id, user_id, session_id, sender_phone, sender_name, message_body, reply_body, direction, status, ai_generated, matched_rule_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         user_id = VALUES(user_id),
         session_id = VALUES(session_id),
         reply_body = VALUES(reply_body),
         status = VALUES(status),
         ai_generated = VALUES(ai_generated),
         matched_rule_id = VALUES(matched_rule_id)`,
      [
        m.id,
        m.user_id || '',
        m.session_id || '',
        m.sender_phone,
        m.sender_name || '',
        m.message_body,
        m.reply_body || '',
        m.direction,
        m.status,
        m.ai_generated ? 1 : 0,
        m.matched_rule_id || '',
        m.created_at
      ]
    );
    if (detectedSchemaMeta.hasWhatsappMessagesTable) {
      await p.query(
        `INSERT INTO whatsapp_messages (id, wam_id, sender_phone, sender_name, message_body, direction, status, reply_body, error_detail, ai_generated, created_at, user_id, session_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           reply_body = VALUES(reply_body),
           status = VALUES(status),
           error_detail = VALUES(error_detail),
           ai_generated = VALUES(ai_generated)`,
        [
          m.id,
          m.wam_id || '',
          m.sender_phone,
          m.sender_name || '',
          m.message_body,
          m.direction,
          m.status,
          m.reply_body || '',
          m.error_detail || '',
          m.ai_generated ? 1 : 0,
          toMysqlDateTime(m.created_at, false),
          m.user_id || '',
          m.session_id || ''
        ]
      ).catch(() => {});
    }
  } catch (e: any) {
    console.warn('[MySQL Sync Message] skipped:', e?.message);
  }
}

export async function clearMessagesFromMysql(userId?: string): Promise<void> {
  if (!isMysqlConfigured()) return;
  try {
    const p = getMysqlPool();
    if (!p) return;
    if (userId) {
      await p.query(`DELETE FROM message_logs WHERE user_id = ?`, [userId]);
      if (detectedSchemaMeta.hasWhatsappMessagesTable) {
        await p.query(`DELETE FROM whatsapp_messages WHERE user_id = ?`, [userId]).catch(() => {});
      }
    } else {
      await p.query(`DELETE FROM message_logs`);
      if (detectedSchemaMeta.hasWhatsappMessagesTable) {
        await p.query(`DELETE FROM whatsapp_messages`).catch(() => {});
      }
    }
  } catch (e: any) {
    console.warn('[MySQL Clear Messages] skipped:', e?.message);
  }
}

export async function pushSessionToMysql(s: WhatsAppSession): Promise<void> {
  if (!isMysqlConfigured()) return;
  try {
    const ok = await initMysqlSchemaIfNotExists();
    if (!ok) return;
    const p = getMysqlPool();
    if (!p) return;
    const cleanPhone = s.phone_number ? s.phone_number.replace(/\D/g, '') : '';
    if (cleanPhone && s.user_id) {
      await p.query(
        `DELETE FROM whatsapp_sessions WHERE REPLACE(REPLACE(phone_number, '+', ''), '-', '') = ? AND user_id = ? AND id != ?`,
        [cleanPhone, s.user_id, s.id]
      ).catch(() => {});
    }
    const cols: string[] = [
      'id', 'user_id', 'session_name', 'phone_number', 'phone_number_id',
      'access_token', 'auth_method', 'status', 'is_primary'
    ];
    const vals: any[] = [
      s.id,
      s.user_id || '',
      s.session_name,
      cleanPhone || s.phone_number,
      '',
      '',
      s.auth_method,
      s.status,
      s.is_primary ? 1 : 0
    ];
    const updates: string[] = [
      'user_id = VALUES(user_id)',
      'session_name = VALUES(session_name)',
      'phone_number = VALUES(phone_number)',
      'auth_method = VALUES(auth_method)',
      'status = VALUES(status)',
      'is_primary = VALUES(is_primary)'
    ];

    if (detectedSchemaMeta.sessionsHasAiEnabled && detectedSchemaMeta.sessionsHasCustomPrompt) {
      cols.push('ai_enabled', 'custom_system_prompt');
      vals.push(
        typeof s.ai_enabled === 'boolean' ? (s.ai_enabled ? 1 : 0) : null,
        typeof s.custom_system_prompt === 'string' ? s.custom_system_prompt : ''
      );
      updates.push('ai_enabled = VALUES(ai_enabled)', 'custom_system_prompt = VALUES(custom_system_prompt)');
    }
    if (detectedSchemaMeta.sessionsHasConnectedAt) {
      cols.push('connected_at');
      vals.push(toMysqlDateTime(s.connected_at, true));
      updates.push('connected_at = VALUES(connected_at)');
    }
    if (detectedSchemaMeta.sessionsHasLastActivityAt) {
      cols.push('last_activity_at');
      vals.push(toMysqlDateTime(s.last_activity_at, true));
      updates.push('last_activity_at = VALUES(last_activity_at)');
    }
    if (detectedSchemaMeta.sessionsHasTotalMessagesCount) {
      cols.push('total_messages_count');
      vals.push(Math.max(0, Number(s.total_messages_count) || 0));
      updates.push('total_messages_count = VALUES(total_messages_count)');
    }

    cols.push('expires_at', 'created_at', 'updated_at');
    vals.push(
      toMysqlDateTime(s.expires_at, true),
      toMysqlDateTime(s.created_at, false),
      toMysqlDateTime(s.updated_at, false)
    );
    updates.push('expires_at = VALUES(expires_at)', 'updated_at = VALUES(updated_at)');

    const placeholders = cols.map(() => '?').join(', ');
    await p.query(
      `INSERT INTO whatsapp_sessions (${cols.join(', ')})
       VALUES (${placeholders})
       ON DUPLICATE KEY UPDATE ${updates.join(', ')}`,
      vals
    );
  } catch (e: any) {
    console.warn('[MySQL Sync Session] skipped:', e?.message);
  }
}

export async function deleteSessionFromMysql(id: string, phoneNumber?: string): Promise<void> {
  if (!isMysqlConfigured()) return;
  try {
    const p = getMysqlPool();
    if (!p) return;
    await p.query(`DELETE FROM whatsapp_sessions WHERE id = ?`, [id]);
    if (phoneNumber) {
      const clean = phoneNumber.replace(/\D/g, '');
      if (clean) {
        await p.query(`DELETE FROM whatsapp_sessions WHERE REPLACE(REPLACE(phone_number, '+', ''), '-', '') = ?`, [clean]);
      }
    }
  } catch (e: any) {
    console.warn('[MySQL Delete Session] skipped:', e?.message);
  }
}

export async function pushBaileysAuthBackupToMysql(
  sessionId: string,
  authFilesMap: Record<string, string>
): Promise<void> {
  if (!isMysqlConfigured()) return;
  try {
    const ok = await initMysqlSchemaIfNotExists();
    if (!ok) return;
    const p = getMysqlPool();
    if (!p) return;
    const { kvKeyCol, kvValCol } = detectedSchemaMeta;
    const kvKey = `baileys_auth_${sessionId}`;
    const encryptedPayload = encryptData(JSON.stringify(authFilesMap));
    const now = toMysqlDateTime(new Date(), false);
    await p.query(
      `INSERT INTO app_kv_store (${kvKeyCol}, ${kvValCol}, updated_at)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE
         ${kvValCol} = VALUES(${kvValCol}),
         updated_at = VALUES(updated_at)`,
      [kvKey, encryptedPayload, now]
    );
  } catch (e: any) {
    console.warn('[MySQL Baileys Auth Backup] skipped:', e?.message);
  }
}

export async function deleteBaileysAuthBackupFromMysql(sessionId: string): Promise<void> {
  if (!isMysqlConfigured()) return;
  try {
    const ok = await initMysqlSchemaIfNotExists();
    if (!ok) return;
    const p = getMysqlPool();
    if (!p) return;
    const { kvKeyCol } = detectedSchemaMeta;
    await p.query(`DELETE FROM app_kv_store WHERE ${kvKeyCol} = ?`, [`baileys_auth_${sessionId}`]);
  } catch {
    // non-fatal
  }
}

export async function fetchAllBaileysAuthBackupsFromMysql(): Promise<Record<string, Record<string, string>>> {
  const result: Record<string, Record<string, string>> = {};
  if (!isMysqlConfigured()) return result;
  try {
    const ok = await initMysqlSchemaIfNotExists();
    if (!ok) return result;
    const p = getMysqlPool();
    if (!p) return result;
    const { kvKeyCol, kvValCol } = detectedSchemaMeta;
    const [rows] = await p.query<mysql.RowDataPacket[]>(
      `SELECT ${kvKeyCol} AS kv_key, ${kvValCol} AS kv_value FROM app_kv_store WHERE ${kvKeyCol} LIKE 'baileys_auth_%'`
    );
    for (const row of rows) {
      if (!row?.kv_key || !row?.kv_value) continue;
      const sessionId = String(row.kv_key).replace(/^baileys_auth_/, '');
      try {
        const raw = decryptData(String(row.kv_value));
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') {
          result[sessionId] = parsed;
        }
      } catch {
        // Ignore corrupted JSON backup
      }
    }
  } catch {
    // Non-fatal
  }
  return result;
}

export async function pushUserToMysql(u: UserAccount): Promise<void> {
  if (!isMysqlConfigured()) return;
  try {
    const ok = await initMysqlSchemaIfNotExists();
    if (!ok) return;
    const p = getMysqlPool();
    if (!p) return;
    const totalMsgCol = detectedSchemaMeta.usersHasTotalMessagesCount ? ', total_messages_count' : '';
    const totalMsgPlaceholder = detectedSchemaMeta.usersHasTotalMessagesCount ? ', ?' : '';
    const totalMsgUpdate = detectedSchemaMeta.usersHasTotalMessagesCount
      ? ',\n         total_messages_count = VALUES(total_messages_count)'
      : '';

    const params: any[] = [
      u.id,
      u.username,
      u.name,
      u.role,
      u.email,
      u.phone || '',
      u.password,
      u.is_active ? 1 : 0,
      u.email_verified ? 1 : 0,
      u.wa_verified ? 1 : 0,
      u.verification_otp || '',
      u.otp_expires_at || '',
      u.plan_id || 'free',
      u.plan_status || 'active',
      u.payment_note || '',
      u.payment_receipt_url || '',
      u.requested_plan_id || '',
      u.ai_verified ? 1 : 0,
      u.ai_verification_notes || '',
      u.ai_verified_at || '',
      u.security_pin || '',
      u.pin_failed_attempts || 0,
      u.is_bot_locked ? 1 : 0,
      u.api_key || '',
      u.custom_gemini_key ? encryptData(u.custom_gemini_key) : '',
      u.custom_offline_message || '',
      u.role === 'admin' ? (u.auto_reply_enabled !== false ? 1 : 0) : (u.auto_reply_enabled === true ? 1 : 0),
      u.auto_reply_activated_at || '',
      u.role === 'admin' ? (u.ai_enabled !== false ? 1 : 0) : (u.ai_enabled === true ? 1 : 0),
      u.meta_ai_verified ? 1 : 0,
      u.meta_ai_verified_phone || '',
      Array.isArray(u.meta_ai_verified_phones) ? JSON.stringify(u.meta_ai_verified_phones) : '[]',
      u.meta_ai_verified_at || '',
      u.custom_system_prompt || '',
      u.role === 'admin' ? (u.default_cs_reply_enabled !== false ? 1 : 0) : (u.default_cs_reply_enabled === true ? 1 : 0),
      u.default_cs_reply_text || '',
      u.allowed_numbers ? JSON.stringify(u.allowed_numbers) : '[]',
      1, // Force 1 max WA session per account
      u.daily_messages_sent || 0,
      u.monthly_messages_sent || 0,
      u.daily_ai_sent || 0,
      u.monthly_ai_sent || 0,
      ...(detectedSchemaMeta.usersHasTotalMessagesCount ? [Math.max(0, Number(u.total_messages_count) || 0)] : []),
      u.last_quota_reset_date || '',
      (u as any).last_quota_reset_month || '',
      u.last_login_device || '',
      u.approved_at || '',
      u.created_at
    ];

    await p.query(
      `INSERT INTO app_users (
        id, username, name, role, email, phone, password,
        is_active, email_verified, wa_verified, verification_otp, otp_expires_at,
        plan_id, plan_status, payment_note, payment_receipt_url, requested_plan_id,
        ai_verified, ai_verification_notes, ai_verified_at,
        security_pin, pin_failed_attempts, is_bot_locked, api_key,
        custom_gemini_key, custom_offline_message, auto_reply_enabled, auto_reply_activated_at, ai_enabled,
        meta_ai_verified, meta_ai_verified_phone, meta_ai_verified_phones, meta_ai_verified_at,
        custom_system_prompt,
        default_cs_reply_enabled, default_cs_reply_text, allowed_numbers,
        max_sessions, daily_messages_sent, monthly_messages_sent, daily_ai_sent, monthly_ai_sent${totalMsgCol},
        last_quota_reset_date, last_quota_reset_month, last_login_device, approved_at, created_at
      )
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?${totalMsgPlaceholder}, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         name = VALUES(name),
         role = VALUES(role),
         email = VALUES(email),
         phone = VALUES(phone),
         password = VALUES(password),
         is_active = VALUES(is_active),
         email_verified = VALUES(email_verified),
         wa_verified = VALUES(wa_verified),
         verification_otp = VALUES(verification_otp),
         otp_expires_at = VALUES(otp_expires_at),
         plan_id = VALUES(plan_id),
         plan_status = VALUES(plan_status),
         payment_note = VALUES(payment_note),
         payment_receipt_url = VALUES(payment_receipt_url),
         requested_plan_id = VALUES(requested_plan_id),
         ai_verified = VALUES(ai_verified),
         ai_verification_notes = VALUES(ai_verification_notes),
         ai_verified_at = VALUES(ai_verified_at),
         security_pin = VALUES(security_pin),
         pin_failed_attempts = VALUES(pin_failed_attempts),
         is_bot_locked = VALUES(is_bot_locked),
         api_key = VALUES(api_key),
         custom_gemini_key = VALUES(custom_gemini_key),
         custom_offline_message = VALUES(custom_offline_message),
         auto_reply_enabled = VALUES(auto_reply_enabled),
         auto_reply_activated_at = VALUES(auto_reply_activated_at),
         ai_enabled = VALUES(ai_enabled),
         meta_ai_verified = VALUES(meta_ai_verified),
         meta_ai_verified_phone = VALUES(meta_ai_verified_phone),
         meta_ai_verified_phones = VALUES(meta_ai_verified_phones),
         meta_ai_verified_at = VALUES(meta_ai_verified_at),
         custom_system_prompt = VALUES(custom_system_prompt),
         default_cs_reply_enabled = VALUES(default_cs_reply_enabled),
         default_cs_reply_text = VALUES(default_cs_reply_text),
         allowed_numbers = VALUES(allowed_numbers),
         max_sessions = VALUES(max_sessions),
         daily_messages_sent = VALUES(daily_messages_sent),
         monthly_messages_sent = VALUES(monthly_messages_sent),
         daily_ai_sent = VALUES(daily_ai_sent),
         monthly_ai_sent = VALUES(monthly_ai_sent)${totalMsgUpdate},
         last_quota_reset_date = VALUES(last_quota_reset_date),
         last_quota_reset_month = VALUES(last_quota_reset_month),
         last_login_device = VALUES(last_login_device),
         approved_at = VALUES(approved_at)`,
      params
    );
  } catch (e: any) {
    console.warn('[MySQL Sync User] skipped:', e?.message);
  }
}

export async function deleteUserFromMysql(id: string): Promise<void> {
  if (!isMysqlConfigured()) return;
  try {
    const p = getMysqlPool();
    if (!p) return;
    await p.query(`DELETE FROM app_users WHERE id = ?`, [id]);
    await p.query(`DELETE FROM whatsapp_sessions WHERE user_id = ?`, [id]);
    await p.query(`DELETE FROM auto_reply_rules WHERE user_id = ?`, [id]);
  } catch (e: any) {
    console.warn('[MySQL Delete User] skipped:', e?.message);
  }
}

export async function pushRuleToMysql(r: AutoReplyRule): Promise<void> {
  if (!isMysqlConfigured()) return;
  try {
    const ok = await initMysqlSchemaIfNotExists();
    if (!ok) return;
    const p = getMysqlPool();
    if (!p) return;
    await p.query(
      `INSERT INTO auto_reply_rules (id, user_id, keyword, match_type, response_text, is_active, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         user_id = VALUES(user_id),
         keyword = VALUES(keyword),
         match_type = VALUES(match_type),
         response_text = VALUES(response_text),
         is_active = VALUES(is_active),
         updated_at = VALUES(updated_at)`,
      [
        r.id,
        r.user_id || '',
        r.keyword,
        r.match_type,
        r.response_text,
        r.is_active ? 1 : 0,
        toMysqlDateTime(r.created_at, false),
        toMysqlDateTime(r.updated_at, false)
      ]
    );
  } catch (e: any) {
    console.warn('[MySQL Sync Rule] skipped:', e?.message);
  }
}

export async function deleteRuleFromMysql(id: string): Promise<void> {
  if (!isMysqlConfigured()) return;
  try {
    const p = getMysqlPool();
    if (!p) return;
    await p.query(`DELETE FROM auto_reply_rules WHERE id = ?`, [id]);
  } catch (e: any) {
    console.warn('[MySQL Delete Rule] skipped:', e?.message);
  }
}

export async function pushSmtpAccountToMysql(s: any): Promise<{ ok: boolean; error?: string }> {
  if (!isMysqlConfigured()) return { ok: true };
  try {
    const ok = await initMysqlSchemaIfNotExists();
    if (!ok) return { ok: false, error: 'Gagal inisialisasi skema database MySQL.' };
    const p = getMysqlPool();
    if (!p) return { ok: false, error: 'Koneksi pool MySQL tidak tersedia.' };
    const { smtpUserCol, smtpPassCol, smtpHasLastError } = detectedSchemaMeta;
    if (smtpHasLastError) {
      await p.query(
        `INSERT INTO smtp_accounts (id, name, host, port, secure, ${smtpUserCol}, ${smtpPassCol}, sender_name, is_active, success_count, error_count, last_error, last_used_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           name = VALUES(name),
           host = VALUES(host),
           port = VALUES(port),
           secure = VALUES(secure),
           ${smtpUserCol} = VALUES(${smtpUserCol}),
           ${smtpPassCol} = VALUES(${smtpPassCol}),
           sender_name = VALUES(sender_name),
           is_active = VALUES(is_active),
           success_count = VALUES(success_count),
           error_count = VALUES(error_count),
           last_error = VALUES(last_error),
           last_used_at = VALUES(last_used_at)`,
        [
          s.id,
          String(s.name || '').slice(0, 128),
          String(s.host || 'smtp.gmail.com').slice(0, 128),
          Number(s.port) || 587,
          s.secure ? 1 : 0,
          String(s.user || '').slice(0, 128),
          String(s.pass || ''),
          String(s.sender_name || '').slice(0, 128),
          s.is_active ? 1 : 0,
          s.success_count || 0,
          s.error_count || 0,
          s.last_error || '',
          toMysqlDateTime(s.last_used_at, true),
          toMysqlDateTime(s.created_at, false)
        ]
      );
    } else {
      await p.query(
        `INSERT INTO smtp_accounts (id, name, host, port, secure, ${smtpUserCol}, ${smtpPassCol}, sender_name, is_active, success_count, error_count, last_used_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           name = VALUES(name),
           host = VALUES(host),
           port = VALUES(port),
           secure = VALUES(secure),
           ${smtpUserCol} = VALUES(${smtpUserCol}),
           ${smtpPassCol} = VALUES(${smtpPassCol}),
           sender_name = VALUES(sender_name),
           is_active = VALUES(is_active),
           success_count = VALUES(success_count),
           error_count = VALUES(error_count),
           last_used_at = VALUES(last_used_at)`,
        [
          s.id,
          String(s.name || '').slice(0, 128),
          String(s.host || 'smtp.gmail.com').slice(0, 128),
          Number(s.port) || 587,
          s.secure ? 1 : 0,
          String(s.user || '').slice(0, 128),
          String(s.pass || ''),
          String(s.sender_name || '').slice(0, 128),
          s.is_active ? 1 : 0,
          s.success_count || 0,
          s.error_count || 0,
          toMysqlDateTime(s.last_used_at, true),
          toMysqlDateTime(s.created_at, false)
        ]
      );
    }
    return { ok: true };
  } catch (e: any) {
    console.warn('[MySQL Sync SMTP] failed:', e?.message);
    return { ok: false, error: 'Gagal menyimpan akun SMTP ke database MySQL.' };
  }
}

export async function deleteSmtpAccountFromMysql(id: string): Promise<{ ok: boolean; error?: string }> {
  if (!isMysqlConfigured()) return { ok: true };
  try {
    const ok = await initMysqlSchemaIfNotExists();
    if (!ok) return { ok: false, error: 'Gagal inisialisasi skema database MySQL.' };
    const p = getMysqlPool();
    if (!p) return { ok: false, error: 'Koneksi pool MySQL tidak tersedia.' };
    await p.query(`DELETE FROM smtp_accounts WHERE id = ?`, [id]);
    return { ok: true };
  } catch (e: any) {
    console.warn('[MySQL Delete SMTP] failed:', e?.message);
    return { ok: false, error: 'Gagal menghapus akun SMTP dari database MySQL.' };
  }
}

export async function pushGeminiKeyToMysql(k: GeminiApiKey): Promise<void> {
  if (!isMysqlConfigured()) return;
  try {
    const ok = await initMysqlSchemaIfNotExists();
    if (!ok) return;
    const p = getMysqlPool();
    if (!p) return;
    const { geminiKeyCol } = detectedSchemaMeta;
    await p.query(
      `INSERT INTO gemini_keys (id, name, ${geminiKeyCol}, is_active, usage_count, error_count, last_used_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         name = VALUES(name),
         ${geminiKeyCol} = VALUES(${geminiKeyCol}),
         is_active = VALUES(is_active),
         usage_count = VALUES(usage_count),
         error_count = VALUES(error_count),
         last_used_at = VALUES(last_used_at)`,
      [
        k.id,
        k.name,
        k.key,
        k.is_active ? 1 : 0,
        k.usage_count || 0,
        k.error_count || 0,
        toMysqlDateTime(k.last_used_at, true),
        toMysqlDateTime(k.created_at, false)
      ]
    );
  } catch (e: any) {
    console.warn('[MySQL Sync Gemini Key] skipped:', e?.message);
  }
}

export async function deleteGeminiKeyFromMysql(id: string): Promise<void> {
  if (!isMysqlConfigured()) return;
  try {
    const p = getMysqlPool();
    if (!p) return;
    await p.query(`DELETE FROM gemini_keys WHERE id = ?`, [id]);
  } catch (e: any) {
    console.warn('[MySQL Delete Gemini] skipped:', e?.message);
  }
}

export async function pushKvSettingToMysql(key: string, value: any): Promise<void> {
  if (!isMysqlConfigured()) return;
  try {
    const ok = await initMysqlSchemaIfNotExists();
    if (!ok) return;
    const p = getMysqlPool();
    if (!p) return;
    const { kvKeyCol, kvValCol } = detectedSchemaMeta;
    const payload = typeof value === 'string' ? value : JSON.stringify(value);
    const stored = key === 'systemConfig' ? encryptData(payload) : payload;
    await p.query(
      `INSERT INTO app_kv_store (${kvKeyCol}, ${kvValCol}, updated_at)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE
         ${kvValCol} = VALUES(${kvValCol}),
         updated_at = VALUES(updated_at)`,
      [key, stored, toMysqlDateTime(new Date(), false)]
    );
  } catch (e: any) {
    console.warn('[MySQL Sync KV] skipped:', e?.message);
  }
}

export async function saveBaileysAuthToMysql(
  sessionId: string,
  authFilesMap: Record<string, string>
): Promise<void> {
  if (!isMysqlConfigured()) return;
  try {
    const ok = await initMysqlSchemaIfNotExists();
    if (!ok) return;
    const p = getMysqlPool();
    if (!p) return;
    const { kvKeyCol, kvValCol } = detectedSchemaMeta;
    const encrypted = encryptData(JSON.stringify(authFilesMap));
    await p.query(
      `INSERT INTO app_kv_store (${kvKeyCol}, ${kvValCol}, updated_at)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE
         ${kvValCol} = VALUES(${kvValCol}),
         updated_at = VALUES(updated_at)`,
      [`baileys_auth_${sessionId}`, encrypted, toMysqlDateTime(new Date(), false)]
    );
  } catch (e: any) {
    console.warn('[MySQL Save Baileys Auth] skipped:', e?.message);
  }
}

export async function loadBaileysAuthFromMysql(
  sessionId: string
): Promise<Record<string, string> | null> {
  if (!isMysqlConfigured()) return null;
  try {
    const ok = await initMysqlSchemaIfNotExists();
    if (!ok) return null;
    const p = getMysqlPool();
    if (!p) return null;
    const { kvKeyCol, kvValCol } = detectedSchemaMeta;
    const [rows] = await p.query<mysql.RowDataPacket[]>(
      `SELECT ${kvValCol} AS kv_value FROM app_kv_store WHERE ${kvKeyCol} = ? LIMIT 1`,
      [`baileys_auth_${sessionId}`]
    );
    if (rows && rows.length > 0 && rows[0].kv_value) {
      const decrypted = decryptData(String(rows[0].kv_value));
      return JSON.parse(decrypted);
    }
    return null;
  } catch {
    return null;
  }
}

export async function loadAllBaileysAuthSessionIdsFromMysql(): Promise<string[]> {
  if (!isMysqlConfigured()) return [];
  try {
    const ok = await initMysqlSchemaIfNotExists();
    if (!ok) return [];
    const p = getMysqlPool();
    if (!p) return [];
    const { kvKeyCol } = detectedSchemaMeta;
    const [rows] = await p.query<mysql.RowDataPacket[]>(
      `SELECT ${kvKeyCol} AS kv_key FROM app_kv_store WHERE ${kvKeyCol} LIKE 'baileys_auth_%'`
    );
    return rows
      .filter(r => r?.kv_key)
      .map(r => String(r.kv_key).replace(/^baileys_auth_/, ''));
  } catch {
    return [];
  }
}

export async function deleteBaileysAuthFromMysql(sessionId: string): Promise<void> {
  if (!isMysqlConfigured()) return;
  try {
    const ok = await initMysqlSchemaIfNotExists();
    if (!ok) return;
    const p = getMysqlPool();
    if (!p) return;
    const { kvKeyCol } = detectedSchemaMeta;
    await p.query(`DELETE FROM app_kv_store WHERE ${kvKeyCol} = ?`, [`baileys_auth_${sessionId}`]);
  } catch {
    // Non-fatal
  }
}

export async function fetchDatabaseFromMysql(): Promise<any | null> {
  if (!isMysqlConfigured()) return null;
  try {
    const ok = await initMysqlSchemaIfNotExists();
    if (!ok) return null;
    const p = getMysqlPool();
    if (!p) return null;

    const { kvKeyCol, kvValCol, hasWhatsappMessagesTable } = detectedSchemaMeta;
    const [msgRows] = await p.query<mysql.RowDataPacket[]>(`SELECT * FROM message_logs ORDER BY created_at DESC LIMIT 1000`);
    const [legacyMsgRows] = hasWhatsappMessagesTable
      ? await p.query<mysql.RowDataPacket[]>(`SELECT * FROM whatsapp_messages ORDER BY created_at DESC LIMIT 1000`).catch(() => [[]] as any)
      : ([[]] as any);
    const mergedMsgMap = new Map<string, any>();
    for (const r of (legacyMsgRows || [])) {
      if (!r?.id) continue;
      mergedMsgMap.set(String(r.id), {
        ...r,
        created_at: fromMysqlDateTime(r.created_at),
        ai_generated: Boolean(r.ai_generated)
      });
    }
    for (const r of msgRows) {
      if (!r?.id) continue;
      mergedMsgMap.set(String(r.id), {
        ...r,
        created_at: fromMysqlDateTime(r.created_at),
        ai_generated: Boolean(r.ai_generated)
      });
    }
    const mergedMessages = Array.from(mergedMsgMap.values())
      .sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime())
      .slice(0, 1000);

    const [sessRows] = await p.query<mysql.RowDataPacket[]>(`SELECT * FROM whatsapp_sessions`);
    const [appUserRows] = await p.query<mysql.RowDataPacket[]>(`SELECT * FROM app_users`);
    const [legacyUserRows] = await p.query<mysql.RowDataPacket[]>(`SELECT * FROM users`).catch(() => [[]] as any);
    const mergedUserMap = new Map<string, mysql.RowDataPacket>();
    for (const r of (legacyUserRows || [])) {
      if (r?.id) mergedUserMap.set(String(r.id), r);
    }
    for (const r of appUserRows) {
      if (r?.id) mergedUserMap.set(String(r.id), r);
    }
    const userRows = Array.from(mergedUserMap.values());
    const [ruleRows] = await p.query<mysql.RowDataPacket[]>(`SELECT * FROM auto_reply_rules`);
    const [smtpRows] = await p.query<mysql.RowDataPacket[]>(`SELECT * FROM smtp_accounts`);
    const [gemRows] = await p.query<mysql.RowDataPacket[]>(`SELECT * FROM gemini_keys`);
    const [kvRows] = await p.query<mysql.RowDataPacket[]>(
      `SELECT ${kvKeyCol} AS kv_key, ${kvValCol} AS kv_value FROM app_kv_store WHERE ${kvKeyCol} NOT LIKE 'baileys_auth_%'`
    );

    const remoteData: any = {
      messages: mergedMessages,
      sessions: sessRows.map(r => ({
        ...r,
        auth_method: r.auth_method === 'pairing_code' ? 'pairing_code' : 'qr_code',
        is_primary: Boolean(r.is_primary),
        ai_enabled: r.ai_enabled === null || r.ai_enabled === undefined ? null : Boolean(r.ai_enabled),
        custom_system_prompt: typeof r.custom_system_prompt === 'string' ? r.custom_system_prompt : '',
        connected_at: fromMysqlDateTime(r.connected_at),
        last_activity_at: fromMysqlDateTime(r.last_activity_at),
        total_messages_count: Number(r.total_messages_count) || 0,
        expires_at: fromMysqlDateTime(r.expires_at),
        created_at: fromMysqlDateTime(r.created_at),
        updated_at: fromMysqlDateTime(r.updated_at)
      })),
      users: userRows.map(r => {
        let parsedAllowed: string[] = [];
        try {
          if (r.allowed_numbers) parsedAllowed = JSON.parse(String(r.allowed_numbers));
        } catch {
          parsedAllowed = [];
        }
        let parsedMetaVerifiedPhones: string[] = [];
        try {
          if (r.meta_ai_verified_phones) parsedMetaVerifiedPhones = JSON.parse(String(r.meta_ai_verified_phones));
        } catch {
          parsedMetaVerifiedPhones = [];
        }
        return {
          ...r,
          is_active: Boolean(r.is_active),
          email_verified: Boolean(r.email_verified),
          wa_verified: Boolean(r.wa_verified),
          ai_verified: Boolean(r.ai_verified),
          meta_ai_verified: Boolean(r.meta_ai_verified),
          meta_ai_verified_phone: r.meta_ai_verified_phone || '',
          meta_ai_verified_phones: Array.isArray(parsedMetaVerifiedPhones) ? parsedMetaVerifiedPhones : [],
          meta_ai_verified_at: r.meta_ai_verified_at || '',
          is_bot_locked: Boolean(r.is_bot_locked),
          pin_failed_attempts: Number(r.pin_failed_attempts) || 0,
          max_sessions: 1,
          daily_messages_sent: Number(r.daily_messages_sent) || 0,
          monthly_messages_sent: Number(r.monthly_messages_sent) || 0,
          daily_ai_sent: Number(r.daily_ai_sent) || 0,
          monthly_ai_sent: Number(r.monthly_ai_sent) || 0,
          total_messages_count: Number(r.total_messages_count) || 0,
          custom_gemini_key: r.custom_gemini_key ? decryptData(String(r.custom_gemini_key)) : '',
          auto_reply_enabled: r.role === 'admin' ? r.auto_reply_enabled !== 0 : Boolean(r.auto_reply_enabled),
          auto_reply_activated_at: r.auto_reply_activated_at || '',
          ai_enabled: r.role === 'admin' ? r.ai_enabled !== 0 : Boolean(r.ai_enabled),
          default_cs_reply_enabled: r.role === 'admin' ? r.default_cs_reply_enabled !== 0 : Boolean(r.default_cs_reply_enabled),
          allowed_numbers: parsedAllowed,
          created_at: fromMysqlDateTime(r.created_at)
        };
      }),
      rules: ruleRows.map(r => ({
        ...r,
        is_active: Boolean(r.is_active),
        created_at: fromMysqlDateTime(r.created_at),
        updated_at: fromMysqlDateTime(r.updated_at)
      })),
      smtpAccounts: smtpRows.map(r => ({
        id: r.id,
        name: r.name,
        host: r.host,
        port: r.port,
        secure: Boolean(r.secure),
        user: r.user_email ?? r.user ?? '',
        pass: r.pass_encrypted ?? r.pass ?? '',
        sender_name: r.sender_name,
        is_active: Boolean(r.is_active),
        success_count: r.success_count,
        error_count: r.error_count,
        last_error: r.last_error ?? '',
        last_used_at: fromMysqlDateTime(r.last_used_at),
        created_at: fromMysqlDateTime(r.created_at)
      })),
      geminiKeys: gemRows.map(r => ({
        id: r.id,
        name: r.name,
        key: r.key_encrypted ?? r.api_key ?? '',
        is_active: Boolean(r.is_active),
        usage_count: r.usage_count,
        error_count: r.error_count,
        last_used_at: fromMysqlDateTime(r.last_used_at),
        created_at: fromMysqlDateTime(r.created_at)
      })),
      kvMap: {} as Record<string, any>
    };

    for (const kv of kvRows) {
      const keyName = kv?.kv_key ?? kv?.setting_key;
      const rawValue = kv?.kv_value ?? kv?.setting_value;
      if (!keyName || typeof keyName !== 'string') continue;
      if (keyName.startsWith('baileys_auth_')) continue;
      if (rawValue === undefined || rawValue === null) continue;
      try {
        const raw = keyName === 'systemConfig' ? decryptData(String(rawValue)) : String(rawValue);
        if (!raw) continue;
        const parsed = JSON.parse(raw);
        remoteData[keyName] = parsed;
        remoteData.kvMap[keyName] = parsed;
      } catch {
        // Ignore unparseable KV entry
      }
    }

    return remoteData;
  } catch (err: any) {
    console.warn('[MySQL Pull] failed:', err?.message);
    return null;
  }
}

export async function testMysqlConnection(configOverride?: MysqlConfigOverride): Promise<{
  connected: boolean;
  host: string;
  port: number;
  database: string;
  version?: string;
  message: string;
  error_code?: string;
  error_detail?: string;
  hint?: string;
  ssl_enabled?: boolean;
  checked_at: string;
}> {
  const cfg = getEffectiveMysqlConfig(configOverride);

  const missingFields: string[] = [];
  if (!cfg.host) missingFields.push('Host');
  if (!cfg.user) missingFields.push('User DB');
  if (!cfg.database) missingFields.push('Nama Database');

  if (missingFields.length > 0) {
    const missingText = missingFields.join(', ');
    return {
      connected: false,
      host: cfg.host || '',
      port: cfg.port,
      database: cfg.database || '',
      ssl_enabled: cfg.ssl,
      error_code: 'MISSING_CONFIG',
      error_detail: `Field wajib belum diisi: ${missingText}.`,
      hint: `Lengkapi ${missingText} melalui Environment Variables / Secrets server (MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE) atau isi form Database Cloud Online lalu klik "Tes Hubungkan".`,
      message: `Konfigurasi MySQL belum lengkap (${missingText} kosong). Sistem berjalan menggunakan penyimpanan lokal aman.`,
      checked_at: new Date().toISOString()
    };
  }

  if (/^\d+$/.test(cfg.host)) {
    return {
      connected: false,
      host: cfg.host,
      port: cfg.port,
      database: cfg.database,
      ssl_enabled: cfg.ssl,
      error_code: 'INVALID_HOST_PORT_MIXUP',
      error_detail: `Nilai MYSQL_HOST terbaca "${cfg.host}" (hanya angka seperti nomor port, bukan alamat IP atau hostname).`,
      hint: `Isi MYSQL_HOST dengan alamat IP server (contoh: 195.88.211.190) atau domain database Anda, dan pastikan angka ${cfg.host} hanya diletakkan di MYSQL_PORT.`,
      message: `Konfigurasi MYSQL_HOST tidak valid ("${cfg.host}" terlihat seperti nomor port).`,
      checked_at: new Date().toISOString()
    };
  }

  let tempConn: mysql.Connection | null = null;
  try {
    const connOptions: mysql.ConnectionOptions = {
      host: cfg.host,
      port: cfg.port,
      user: cfg.user,
      password: cfg.password,
      database: cfg.database,
      connectTimeout: 6000
    };
    if (cfg.ssl) {
      connOptions.ssl = {
        rejectUnauthorized: process.env.MYSQL_SSL_REJECT_UNAUTHORIZED !== 'false'
      };
    }

    tempConn = await mysql.createConnection(connOptions);
    const [rows] = await tempConn.query<mysql.RowDataPacket[]>(`SELECT VERSION() AS version`);
    const version = rows[0]?.version || 'MySQL Online';
    return {
      connected: true,
      host: cfg.host,
      port: cfg.port,
      database: cfg.database,
      version,
      ssl_enabled: cfg.ssl,
      message: `Terhubung ke MySQL Server (${version}) di ${cfg.host}:${cfg.port}/${cfg.database}`,
      checked_at: new Date().toISOString()
    };
  } catch (err: any) {
    const diag = formatMysqlErrorDiagnostic(err, cfg);
    return {
      connected: false,
      host: cfg.host,
      port: cfg.port,
      database: cfg.database,
      ssl_enabled: cfg.ssl,
      error_code: diag.code,
      error_detail: diag.detail,
      hint: diag.hint,
      message: `Koneksi MySQL gagal [${diag.code}]: ${diag.detail}`,
      checked_at: new Date().toISOString()
    };
  } finally {
    if (tempConn) await tempConn.end().catch(() => {});
  }
}

export async function syncPushStructureAndData(configOverride?: MysqlConfigOverride): Promise<{
  success: boolean;
  message: string;
  logs: string[];
}> {
  const logs: string[] = [];
  const cfg = getEffectiveMysqlConfig(configOverride);
  if (!cfg.host || !cfg.user || !cfg.database) {
    return {
      success: false,
      message: 'Host, User, dan Database MySQL wajib diisi sebelum sinkronisasi.',
      logs: ['✗ Konfigurasi MySQL belum lengkap (Host / User / Database kosong).']
    };
  }

  try {
    isSchemaInitialized = false;
    const ok = await initMysqlSchemaIfNotExists(configOverride);
    if (!ok) {
      const errMsg = lastSchemaInitError
        ? `[${lastSchemaInitError.code}] ${lastSchemaInitError.detail}`
        : 'Koneksi atau pembuatan skema tabel gagal.';
      logs.push(`✗ Gagal membuat struktur tabel MySQL: ${errMsg}`);
      if (lastSchemaInitError?.hint) {
        logs.push(`ℹ Saran: ${lastSchemaInitError.hint}`);
      }
      return {
        success: false,
        message: `Tidak dapat menginisialisasi tabel MySQL: ${errMsg}`,
        logs
      };
    }
    logs.push(`✓ Struktur tabel MySQL berhasil dibuat / diverifikasi (${cfg.host}:${cfg.port}/${cfg.database}).`);

    const db = initDbFile();

    let countUsers = 0;
    for (const u of db.users || []) {
      await pushUserToMysql(u);
      countUsers++;
    }
    logs.push(`✓ ${countUsers} akun pengguna disinkronkan.`);

    let countRules = 0;
    for (const r of db.rules || []) {
      await pushRuleToMysql(r);
      countRules++;
    }
    logs.push(`✓ ${countRules} aturan balasan otomatis disinkronkan.`);

    let countSess = 0;
    for (const s of db.sessions || []) {
      await pushSessionToMysql(s);
      countSess++;
    }
    logs.push(`✓ ${countSess} sesi WhatsApp disinkronkan.`);

    let countSmtp = 0;
    for (const s of db.smtpAccounts || []) {
      await pushSmtpAccountToMysql(s);
      countSmtp++;
    }
    logs.push(`✓ ${countSmtp} akun SMTP disinkronkan.`);

    await pushKvSettingToMysql('plans', db.plans);
    await pushKvSettingToMysql('antiBan', db.antiBan);
    await pushKvSettingToMysql('qris', db.systemConfig?.qris_config || {});
    await pushKvSettingToMysql('systemConfig', db.systemConfig);
    await pushKvSettingToMysql('stats', db.stats);
    await pushKvSettingToMysql('broadcastHistory', db.broadcastHistory || []);
    await pushKvSettingToMysql('catalogProducts', db.catalogProducts || []);
    await pushKvSettingToMysql('catalogSettings', db.catalogSettings || {});
    await pushKvSettingToMysql('superadminWaQueue', db.superadminWaQueue || []);
    await pushKvSettingToMysql('expiredSessionAlertKeys', db.expiredSessionAlertKeys || {});
    await pushKvSettingToMysql('pendingSessionExpiryAlerts', db.pendingSessionExpiryAlerts || []);
    logs.push('✓ Konfigurasi paket, anti-ban, QRIS, katalog Mini Shop, antrean WA Superadmin, dan pengaturan sistem disinkronkan.');

    return {
      success: true,
      message: 'Struktur tabel & seluruh data berhasil disinkronkan ke MySQL!',
      logs
    };
  } catch (err: any) {
    const diag = formatMysqlErrorDiagnostic(err, cfg);
    logs.push(`✗ Error sinkronisasi [${diag.code}]: ${diag.detail}`);
    logs.push(`ℹ Saran: ${diag.hint}`);
    return {
      success: false,
      message: `Gagal sinkronisasi ke MySQL [${diag.code}]: ${diag.detail}`,
      logs
    };
  }
}
