import makeWASocketImport, {
  useMultiFileAuthState,
  makeCacheableSignalKeyStore,
  generateMessageIDV2,
  DisconnectReason,
  fetchLatestBaileysVersion,
  delay
} from '@whiskeysockets/baileys';
import crypto from 'crypto';
import pino from 'pino';
import QRCode from 'qrcode';
import path from 'path';
import fs from 'fs';
import {
  updateSession,
  addSession,
  deleteSession,
  getSessionById,
  getSessionsByUserId,
  getWhatsAppSessions,
  addMessageLog,
  addBroadcastHistory,
  getAntiBanSettings,
  getSystemConfig,
  getUserById,
  canUseAiQuota,
  deductUserAiQuota,
  deductUserDailyQuota,
  initDbFile,
  extractUserIdFromSessionId,
  isSessionOwnedByUserId,
  getActiveCatalogForAi,
  resolveOrderNotificationRecipientPhone,
  getSuperadminWaQueue,
  enqueueSuperadminWaMessage,
  updateSuperadminWaQueueItem,
  removeSuperadminWaQueueItem,
  isPhoneMetaAiVerifiedForUser,
  markUserMetaAiVerified,
  updateUser,
  resolveEffectiveSessionAiSettings,
  getWhitelabelConfig,
  resolvePublicAppBaseUrl,
  hasSessionExpiryAlertSent,
  markSessionExpiryAlertSent,
  clearSessionExpiryAlertSent,
  getPendingSessionExpiryAlerts,
  upsertPendingSessionExpiryAlert,
  removePendingSessionExpiryAlert,
  clearPendingSessionExpiryAlertsByKeys,
  getUserAutoReplyStatus,
  recordSessionMessageActivity,
  SESSION_INACTIVITY_PURGE_MS
} from './db.js';
import {
  askMetaAiViaBaileys,
  attachMetaAiRawSocketHandlers,
  clearMetaAiSession,
  handleMetaAiIncomingUpdate,
  handleMetaAiIncomingUpsert,
  isMetaAiJid,
  registerConnectedSocketProvider,
  type ConnectedSocketEntry
} from './metaAiService.js';
import { recordAiAuditEvent } from './aiAuditLogger.js';
import {
  isMysqlConfigured,
  saveBaileysAuthToMysql,
  loadBaileysAuthFromMysql,
  loadAllBaileysAuthSessionIdsFromMysql,
  deleteBaileysAuthFromMysql
} from './mysqlService.js';
import {
  buildDeterministicOrderFallbackReply,
  completeAndConsumeVerifiedPaidOrder,
  formatOwnerOrderNotificationMessage,
  parseAndHandleAiPaymentDirectives,
  prepareOrderFlowForIncomingMessage,
  recordCustomerTurn
} from './orderAssistant.js';

// Consistent Browser & Version across ALL Baileys sockets (prevents "Periksa nomor dengan benar" on pairing restart)
export const BAILEYS_BROWSER: [string, string, string] = ['Ubuntu', 'Chrome', '22.04.4'];
export const DEFAULT_BAILEYS_VERSION: [number, number, number] = [2, 3000, 1043857760];
const BAILEYS_SILENT_LOGGER = pino({ level: 'silent' });

let cachedBaileysVersion: [number, number, number] | null = null;
let versionFetchPromise: Promise<[number, number, number]> | null = null;

async function resolveBaileysVersion(): Promise<[number, number, number]> {
  if (cachedBaileysVersion) return cachedBaileysVersion;
  if (versionFetchPromise) return versionFetchPromise;

  versionFetchPromise = Promise.race([
    fetchLatestBaileysVersion().then(res => res.version as [number, number, number]),
    new Promise<[number, number, number]>(resolve =>
      setTimeout(() => resolve(DEFAULT_BAILEYS_VERSION), 3500)
    )
  ])
    .catch(() => DEFAULT_BAILEYS_VERSION)
    .then(ver => {
      cachedBaileysVersion = ver || DEFAULT_BAILEYS_VERSION;
      versionFetchPromise = null;
      return cachedBaileysVersion;
    });

  return versionFetchPromise;
}

function isSocketTrulyOpen(sock: any): boolean {
  if (!sock) return false;
  if (sock.ws) {
    if (sock.ws.isClosed === true) return false;
    if (typeof sock.ws.isOpen === 'boolean') return sock.ws.isOpen;
    if (typeof sock.ws.readyState === 'number') return sock.ws.readyState === 1;
    if (typeof sock.ws.socket?.readyState === 'number') return sock.ws.socket.readyState === 1;
  }
  return true;
}

function isSocketConnecting(sock: any): boolean {
  if (!sock?.ws) return false;
  if (typeof sock.ws.isConnecting === 'boolean') return sock.ws.isConnecting;
  if (typeof sock.ws.readyState === 'number') return sock.ws.readyState === 0;
  if (typeof sock.ws.socket?.readyState === 'number') return sock.ws.socket.readyState === 0;
  return false;
}

// Normalize phone number to international WhatsApp format (e.g. 0812..., 812..., +62812... -> 62812...)
export function normalizePhoneNumber(phone: string): string {
  if (!phone) return '';
  let clean = phone.replace(/\D/g, '');
  if (clean.startsWith('00')) {
    clean = clean.slice(2);
  }
  if (clean.startsWith('620')) {
    clean = '62' + clean.slice(3);
  } else if (clean.startsWith('0')) {
    clean = '62' + clean.slice(1);
  } else if (clean.startsWith('8')) {
    clean = '62' + clean;
  }
  return clean;
}

// Handle ESM/CJS default export compatibility for Baileys
const makeWASocket = (makeWASocketImport as any).default || makeWASocketImport;

interface SessionState {
  sessionId: string;
  userId?: string;
  socket: any;
  qrCodeUrl: string | null;
  pairingCode: string | null;
  status: 'connecting' | 'connected' | 'disconnected';
  phoneNumber: string | null;
  lastUpdated: number;
  lastOutgoingAt?: number;
  handshakeStartedAt: number;
  retryCount: number;
  disconnectedSince?: number;
  is_primary?: boolean;
  detachRawHandlers?: () => void;
}

const activeSessions = new Map<string, SessionState>();
const sessionStartLocks = new Map<string, Promise<SessionState>>();
const authBackupTimers = new Map<string, NodeJS.Timeout>();
const lastAuthBackupAt = new Map<string, number>();
const lastAuthBackupHashes = new Map<string, string>();
const reconnectTimers = new Map<string, NodeJS.Timeout>();
const inFlightExpiryAlerts = new Set<string>();
const recentMessageProtoCache = new Map<string, any>();
const sessionDisconnectDiagnostics = new Map<string, { code?: number; reason: string; at: number }>();
const AUTH_DIR = path.resolve(process.cwd(), 'baileys_auth_sessions');
const UNSCANNED_HANDSHAKE_TTL_MS = 3 * 60 * 1000;
const AUTH_BACKUP_DEBOUNCE_MS = 4000;
const AUTH_BACKUP_COOLDOWN_MS = 15000;
const PRUNE_COOLDOWN_MS = 120000;
const MYSQL_AUTH_PRUNE_INTERVAL_MS = 10 * 60 * 1000;
const SESSION_EXPIRY_ALERT_GRACE_MS = 60 * 60 * 1000; // Tunggu 1 jam sebelum kirim WA pengingat kedaluwarsa

function createTtlCacheStore(ttlMs: number, maxEntries: number = 1500) {
  const store = new Map<string, { val: unknown; exp: number }>();
  const purgeIfNeeded = () => {
    if (store.size <= maxEntries) return;
    const now = Date.now();
    for (const [k, entry] of store.entries()) {
      if (entry.exp <= now) store.delete(k);
    }
    while (store.size > maxEntries) {
      const oldestKey = store.keys().next().value;
      if (!oldestKey) break;
      store.delete(oldestKey);
    }
  };
  return {
    get<T>(key: string): T | undefined {
      const entry = store.get(key);
      if (!entry) return undefined;
      if (entry.exp <= Date.now()) {
        store.delete(key);
        return undefined;
      }
      return entry.val as T;
    },
    set<T>(key: string, value: T): boolean {
      store.delete(key);
      store.set(key, { val: value, exp: Date.now() + ttlMs });
      purgeIfNeeded();
      return true;
    },
    del(key: string): number {
      return store.delete(key) ? 1 : 0;
    },
    flushAll(): void {
      store.clear();
    },
    mget<T>(keys: string[]): Promise<Record<string, T | undefined>> {
      const out: Record<string, T | undefined> = {};
      const now = Date.now();
      for (const key of keys) {
        const entry = store.get(key);
        if (entry && entry.exp > now) {
          out[key] = entry.val as T;
        } else if (entry) {
          store.delete(key);
        }
      }
      return Promise.resolve(out);
    },
    mset<T>(entries: Array<{ key: string; value: T }>): boolean {
      const exp = Date.now() + ttlMs;
      for (const { key, value } of entries) {
        store.delete(key);
        store.set(key, { val: value, exp });
      }
      purgeIfNeeded();
      return true;
    },
    close(): void {
      // Keep warm across brief reconnects; explicit cleanup clears session caches
    }
  };
}

const sessionUserDevicesCaches = new Map<string, ReturnType<typeof createTtlCacheStore>>();
const sessionMsgRetryCaches = new Map<string, ReturnType<typeof createTtlCacheStore>>();
const sessionSignalKeyStores = new Map<string, any>();

function getSessionCacheStores(sessionId: string) {
  let userDevicesCache = sessionUserDevicesCaches.get(sessionId);
  if (!userDevicesCache) {
    userDevicesCache = createTtlCacheStore(5 * 60 * 1000, 1500);
    sessionUserDevicesCaches.set(sessionId, userDevicesCache);
  }
  let msgRetryCounterCache = sessionMsgRetryCaches.get(sessionId);
  if (!msgRetryCounterCache) {
    msgRetryCounterCache = createTtlCacheStore(10 * 60 * 1000, 800);
    sessionMsgRetryCaches.set(sessionId, msgRetryCounterCache);
  }
  return { userDevicesCache, msgRetryCounterCache };
}

function clearSessionCacheStores(sessionId: string) {
  sessionUserDevicesCaches.get(sessionId)?.flushAll();
  sessionUserDevicesCaches.delete(sessionId);
  sessionMsgRetryCaches.get(sessionId)?.flushAll();
  sessionMsgRetryCaches.delete(sessionId);
  sessionSignalKeyStores.delete(sessionId);
}

export function buildCachedAuthState(sessionId: string, state: any) {
  const cachedKeys = makeCacheableSignalKeyStore(state.keys, BAILEYS_SILENT_LOGGER);
  sessionSignalKeyStores.set(sessionId, cachedKeys);
  return {
    creds: state.creds,
    keys: cachedKeys
  };
}

function rememberProtoMessage(key: { remoteJid?: string | null; id?: string | null }, message: any) {
  const id = key?.id ? String(key.id) : '';
  if (!id || !message) return;
  const cacheKey = `${key?.remoteJid || ''}:${id}`;
  if (recentMessageProtoCache.has(cacheKey)) {
    recentMessageProtoCache.delete(cacheKey);
  }
  recentMessageProtoCache.set(cacheKey, message);
  if (recentMessageProtoCache.size > 250) {
    const oldest = recentMessageProtoCache.keys().next().value;
    if (oldest) recentMessageProtoCache.delete(oldest);
  }
}

function recordDisconnectDiagnostic(sessionId: string, statusCode?: number, errMessage?: string) {
  let reason = `status_${statusCode ?? 'unknown'}`;
  if (statusCode === DisconnectReason.loggedOut || statusCode === 401) {
    reason = '401_logged_out_dari_hp_atau_server_wa';
  } else if (statusCode === DisconnectReason.connectionReplaced || statusCode === 440) {
    reason = '440_konflik_koneksi_ganda';
  } else if (statusCode === DisconnectReason.badSession || statusCode === 500) {
    reason = '500_bad_session_key_desync';
  } else if (statusCode === DisconnectReason.restartRequired || statusCode === 515) {
    reason = '515_restart_required';
  } else if (statusCode === DisconnectReason.timedOut || statusCode === 408) {
    reason = '408_websocket_timeout';
  } else if (statusCode === DisconnectReason.connectionClosed || statusCode === 428) {
    reason = '428_connection_closed';
  } else if (errMessage) {
    reason = `${statusCode ?? 'err'}: ${errMessage.slice(0, 100)}`;
  }
  sessionDisconnectDiagnostics.set(sessionId, {
    code: statusCode,
    reason,
    at: Date.now()
  });
}

export function clearSessionExpiryNotificationCooldown(sessionId: string, ownerUserId?: string, phone?: string) {
  const cleanPhone = normalizePhoneNumber(phone || '');
  const keysToClear: string[] = [];
  if (sessionId) keysToClear.push(sessionId);
  if (ownerUserId) {
    if (sessionId) keysToClear.push(`${ownerUserId}:${sessionId}`);
    if (cleanPhone) keysToClear.push(`${ownerUserId}:${cleanPhone}`);
  }
  clearSessionExpiryAlertSent(keysToClear);
  clearPendingSessionExpiryAlertsByKeys({
    userId: ownerUserId,
    sessionId,
    phone: cleanPhone
  });
}

function verifyExpiredAlertState(params: {
  userId: string;
  sessionId: string;
  expiredPhone?: string;
}): 'expired' | 'recovered' | 'wait' {
  const owner = getUserById(params.userId);
  if (!isOwnerActiveAndRegistered(owner)) {
    return 'recovered';
  }

  const now = Date.now();
  const cleanPhone = normalizePhoneNumber(params.expiredPhone || '');

  // 1. Check live in-memory sockets for this user
  for (const s of activeSessions.values()) {
    const ownerMatch =
      s.userId === owner!.id ||
      isSessionOwnedByUserId(s.sessionId, owner!.id) ||
      Boolean(getSessionById(s.sessionId)?.user_id === owner!.id);
    if (!ownerMatch) continue;

    const memPhone = normalizePhoneNumber(s.phoneNumber || '');
    const sameDevice =
      s.sessionId === params.sessionId ||
      (cleanPhone.length >= 8 && memPhone === cleanPhone);
    if (!sameDevice) continue;

    if (s.status === 'connected' && isSocketTrulyOpen(s.socket)) {
      return 'recovered';
    }
    if (s.status === 'connecting' && now - s.lastUpdated < 45000) {
      return 'wait';
    }
  }

  // 2. Check persisted DB sessions for this user (covers connected & valid standby devices)
  const userDbSessions = getSessionsByUserId(owner!.id);
  for (const s of userDbSessions) {
    const dbPhone = normalizePhoneNumber(s.phone_number || '');
    const sameDevice =
      s.id === params.sessionId ||
      (cleanPhone.length >= 8 && dbPhone === cleanPhone);
    if (!sameDevice) continue;

    const notExpiredByDate = !s.expires_at || Date.parse(s.expires_at) > now;
    if (s.status === 'connected' && notExpiredByDate && hasRegisteredCredsOnDisk(s.id)) {
      return 'recovered';
    }
  }

  return 'expired';
}

function buildProfessionalExpiredSessionMessage(params: {
  ownerName: string;
  expiredPhone?: string;
  sessionName?: string;
}): string {
  const wl = getWhitelabelConfig();
  const appName = (wl?.app_name || 'Japriin').trim();
  const publicUrl = resolvePublicAppBaseUrl();
  const cleanPhone = normalizePhoneNumber(params.expiredPhone || '');
  const deviceLabel = cleanPhone
    ? `+${cleanPhone}`
    : params.sessionName && !params.sessionName.startsWith('session_')
      ? params.sessionName
      : 'Perangkat WhatsApp Anda';
  const urlBlock = publicUrl ? `\nTautan login: ${publicUrl}\n` : '\n';

  return (
    `Halo *${params.ownerName}*,\n\n` +
    `Kami informasikan bahwa tautan perangkat WhatsApp Anda (*${deviceLabel}*) di *${appName}* saat ini sudah kedaluwarsa atau terputus selama lebih dari 1 jam.\n\n` +
    `Silakan login ke akun *${appName}* Anda dan tautkan kembali perangkat pada menu *Koneksi WA* agar sesi dan layanan pengiriman pesan Anda kembali berjalan lancar.${urlBlock}\n` +
    `Terima kasih.\n` +
    `_Pesan pengingat ini hanya dikirim satu kali sampai perangkat Anda ditautkan kembali._`
  );
}

export async function notifyUserSessionExpired(params: {
  sessionId: string;
  sessionName?: string;
  expiredPhone?: string;
  userId?: string;
  reason?: string;
  graceMs?: number;
}): Promise<{ notified: boolean; skipped?: string; queued?: boolean; scheduled?: boolean }> {
  const dbSess = getSessionById(params.sessionId);
  const resolvedPhone = normalizePhoneNumber(
    params.expiredPhone || dbSess?.phone_number || getCredsPhoneOnDisk(params.sessionId) || ''
  );
  const owner = resolveActiveVerifiedOwner(params.sessionId, params.userId || dbSess?.user_id, resolvedPhone);
  if (!isOwnerActiveAndRegistered(owner)) {
    return { notified: false, skipped: 'owner_inactive' };
  }

  const recipientPhone = normalizePhoneNumber(owner!.phone || '');
  if (!recipientPhone || recipientPhone.length < 8) {
    return { notified: false, skipped: 'missing_owner_phone' };
  }

  const dedupeKeys = Array.from(
    new Set(
      [
        resolvedPhone ? `${owner!.id}:${resolvedPhone}` : `${owner!.id}:${params.sessionId}`,
        `${owner!.id}:${params.sessionId}`
      ].filter(Boolean)
    )
  );

  if (dedupeKeys.some(k => inFlightExpiryAlerts.has(k)) || hasSessionExpiryAlertSent(dedupeKeys)) {
    return { notified: false, skipped: 'already_notified_until_relogin' };
  }

  const alertKey = resolvedPhone ? `${owner!.id}:${resolvedPhone}` : `${owner!.id}:${params.sessionId}`;
  const graceMs = typeof params.graceMs === 'number' && params.graceMs >= 0 ? params.graceMs : SESSION_EXPIRY_ALERT_GRACE_MS;

  const { item, created } = upsertPendingSessionExpiryAlert({
    key: alertKey,
    user_id: owner!.id,
    session_id: params.sessionId,
    session_name: params.sessionName || dbSess?.session_name,
    expired_phone: resolvedPhone || undefined,
    reason: params.reason,
    grace_ms: graceMs
  });

  if (created) {
    console.log(
      `[Baileys Expiry Alert Scheduled] User=${owner!.username} Session=${params.sessionId} (+${resolvedPhone || '-'}) ditunda 1 jam (kirim setelah ${item.notify_after}).`
    );
  }

  return { notified: false, scheduled: true, queued: false };
}

let isProcessingPendingExpiryAlerts = false;
export async function processPendingSessionExpiryAlerts(reason = 'watchdog'): Promise<{
  checked: number;
  sent: number;
  cancelled: number;
  waiting: number;
}> {
  if (isProcessingPendingExpiryAlerts) {
    return { checked: 0, sent: 0, cancelled: 0, waiting: 0 };
  }

  const pending = getPendingSessionExpiryAlerts();
  if (pending.length === 0) {
    return { checked: 0, sent: 0, cancelled: 0, waiting: 0 };
  }

  isProcessingPendingExpiryAlerts = true;
  let checked = 0;
  let sent = 0;
  let cancelled = 0;
  let waiting = 0;

  try {
    const now = Date.now();
    for (const alert of pending) {
      checked++;

      // Selalu cek ulang status sesi user (bahkan sebelum 1 jam) agar jika sudah pulih langsung dibatalkan
      const preCheck = verifyExpiredAlertState({
        userId: alert.user_id,
        sessionId: alert.session_id,
        expiredPhone: alert.expired_phone
      });
      if (preCheck === 'recovered') {
        removePendingSessionExpiryAlert(alert.id);
        cancelled++;
        continue;
      }

      const notifyAfterMs = Date.parse(alert.notify_after || '');
      if (Number.isFinite(notifyAfterMs) && now < notifyAfterMs) {
        waiting++;
        continue;
      }

      if (preCheck === 'wait') {
        waiting++;
        continue;
      }

      const owner = getUserById(alert.user_id);
      if (!isOwnerActiveAndRegistered(owner)) {
        removePendingSessionExpiryAlert(alert.id);
        cancelled++;
        continue;
      }

      const recipientPhone = normalizePhoneNumber(owner!.phone || '');
      if (!recipientPhone || recipientPhone.length < 8) {
        removePendingSessionExpiryAlert(alert.id);
        cancelled++;
        continue;
      }

      const cleanExpiredPhone = normalizePhoneNumber(alert.expired_phone || '');
      const dedupeKeys = Array.from(
        new Set(
          [
            cleanExpiredPhone ? `${owner!.id}:${cleanExpiredPhone}` : `${owner!.id}:${alert.session_id}`,
            `${owner!.id}:${alert.session_id}`
          ].filter(Boolean)
        )
      );

      if (hasSessionExpiryAlertSent(dedupeKeys)) {
        removePendingSessionExpiryAlert(alert.id);
        cancelled++;
        continue;
      }

      // Tunggu sampai WA Superadmin benar-benar terhubung
      const saSession = resolveConnectedSuperadminSession();
      if (!saSession) {
        waiting++;
        continue;
      }

      // Hindari self-notif jika satu-satunya admin WA yang terhubung justru nomor yg sama & tidak punya sesi lain
      if (owner!.role === 'admin' && saSession.sessionId === alert.session_id) {
        waiting++;
        continue;
      }

      // Verifikasi ulang TERAKHIR tepat sebelum mengirim agar tidak salah kirim info ke user
      const finalCheck = verifyExpiredAlertState({
        userId: alert.user_id,
        sessionId: alert.session_id,
        expiredPhone: alert.expired_phone
      });
      if (finalCheck === 'recovered') {
        removePendingSessionExpiryAlert(alert.id);
        cancelled++;
        continue;
      }
      if (finalCheck === 'wait') {
        waiting++;
        continue;
      }

      if (dedupeKeys.some(k => inFlightExpiryAlerts.has(k))) {
        waiting++;
        continue;
      }

      const message = buildProfessionalExpiredSessionMessage({
        ownerName: owner!.name || owner!.username,
        expiredPhone: alert.expired_phone,
        sessionName: alert.session_name
      });

      for (const k of dedupeKeys) inFlightExpiryAlerts.add(k);
      try {
        await sendDirectlyViaSuperadminSocket(saSession, recipientPhone, message);
        markSessionExpiryAlertSent(dedupeKeys);
        removePendingSessionExpiryAlert(alert.id);
        sent++;
        console.log(
          `[Baileys Expiry Alert Sent:${reason}] User=${owner!.username} (${recipientPhone}) ExpiredPhone=+${cleanExpiredPhone || '-'} Session=${alert.session_id}`
        );
        if (pending.length > 1) {
          await delay(3500 + crypto.randomInt(0, 1500));
        }
      } catch (err: any) {
        waiting++;
        console.warn(
          `[Baileys Expiry Alert Retry] Gagal kirim notifikasi expired ke ${recipientPhone}, ditahan untuk percobaan berikutnya:`,
          err?.message || err
        );
      } finally {
        for (const k of dedupeKeys) inFlightExpiryAlerts.delete(k);
      }
    }
  } finally {
    isProcessingPendingExpiryAlerts = false;
  }

  return { checked, sent, cancelled, waiting };
}

export function buildBaileysSocketConfig(
  version: [number, number, number],
  logger: any,
  authState: any,
  extraCaches?: { userDevicesCache?: any; msgRetryCounterCache?: any }
) {
  return {
    version,
    logger,
    printQRInTerminal: false,
    auth: authState,
    browser: BAILEYS_BROWSER,
    syncFullHistory: false,
    shouldSyncHistoryMessage: () => false,
    generateHighQualityLinkPreview: false,
    linkPreviewImageThumbnailWidth: 0,
    markOnlineOnConnect: false,
    shouldIgnoreJid: (jid: string) => {
      if (!jid) return false;
      if (isMetaAiJid(jid)) return false;
      return (
        jid.endsWith('@g.us') ||
        jid === 'status@broadcast' ||
        jid.endsWith('@broadcast') ||
        jid.endsWith('@newsletter')
      );
    },
    connectTimeoutMs: 30000,
    defaultQueryTimeoutMs: 20000,
    keepAliveIntervalMs: 15000,
    qrTimeout: 60000,
    retryRequestDelayMs: 1000,
    maxMsgRetryCount: 4,
    ...(extraCaches?.userDevicesCache ? { userDevicesCache: extraCaches.userDevicesCache } : {}),
    ...(extraCaches?.msgRetryCounterCache ? { msgRetryCounterCache: extraCaches.msgRetryCounterCache } : {}),
    getMessage: async (key: { remoteJid?: string | null; id?: string | null }) => {
      if (!key?.id) return undefined;
      return (
        recentMessageProtoCache.get(`${key.remoteJid || ''}:${key.id}`) ||
        undefined
      );
    },
    transactionOpts: {
      maxCommitRetries: 5,
      delayBetweenTriesMs: 500
    }
  };
}

const ensureSessionLocks = new Map<string, Promise<ConnectedSocketEntry | null>>();

function socketMatchesUser(
  s: SessionState,
  userId: string,
  userDbSessions?: Array<{ id: string; user_id?: string; phone_number?: string }>
): boolean {
  if (!userId) return true;
  if (s.userId && s.userId !== userId) return false;
  if (s.userId === userId || isSessionOwnedByUserId(s.sessionId, userId)) {
    if (!s.userId) s.userId = userId;
    return true;
  }
  const dbSess = getSessionById(s.sessionId);
  if (dbSess?.user_id) {
    if (dbSess.user_id !== userId) return false;
    if (!s.userId) s.userId = userId;
    return true;
  }
  const ownedSessions = userDbSessions ?? getSessionsByUserId(userId);
  const memPhone = normalizePhoneNumber(s.phoneNumber || '');
  const matched = ownedSessions.some(
    dbS =>
      dbS.id === s.sessionId ||
      (memPhone.length >= 8 &&
        dbS.phone_number &&
        normalizePhoneNumber(dbS.phone_number) === memPhone)
  );
  if (matched && !s.userId) {
    s.userId = userId;
  }
  return matched;
}

function findLiveSocketEntry(
  userId?: string,
  preferredSessionId?: string
): ConnectedSocketEntry | null {
  const userDbSessions = userId ? getSessionsByUserId(userId) : undefined;
  if (preferredSessionId) {
    const pref = activeSessions.get(preferredSessionId);
    if (
      pref &&
      pref.status === 'connected' &&
      pref.socket &&
      isSocketTrulyOpen(pref.socket) &&
      (!userId || socketMatchesUser(pref, userId, userDbSessions))
    ) {
      return {
        sessionId: pref.sessionId,
        userId: pref.userId,
        phoneNumber: pref.phoneNumber || undefined,
        socket: pref.socket
      };
    }
  }

  const candidates = Array.from(activeSessions.values()).filter((s) => {
    if (s.status !== 'connected' || !s.socket || !isSocketTrulyOpen(s.socket)) return false;
    return !userId || socketMatchesUser(s, userId, userDbSessions);
  });

  const picked = candidates.find((s) => s.is_primary) || candidates[0];
  if (!picked) return null;
  return {
    sessionId: picked.sessionId,
    userId: picked.userId,
    phoneNumber: picked.phoneNumber || undefined,
    socket: picked.socket
  };
}

export async function ensureConnectedSessionForUser(
  userId?: string,
  preferredSessionId?: string
): Promise<ConnectedSocketEntry | null> {
  const immediate = findLiveSocketEntry(userId, preferredSessionId);
  if (immediate) return immediate;
  if (!userId && !preferredSessionId) return null;

  const lockKey = `${userId || ''}::${preferredSessionId || ''}`;
  const inFlight = ensureSessionLocks.get(lockKey);
  if (inFlight) return inFlight;

  const promise = (async (): Promise<ConnectedSocketEntry | null> => {
    try {
      const userDbSessions = userId ? getSessionsByUserId(userId) : [];

      // 1. Wait briefly if an owned session is currently mid-handshake / reconnecting
      const connectingMatch = Array.from(activeSessions.values()).find((s) => {
        if (s.status !== 'connecting') return false;
        if (preferredSessionId && s.sessionId === preferredSessionId) {
          return !userId || socketMatchesUser(s, userId, userDbSessions);
        }
        return userId ? socketMatchesUser(s, userId, userDbSessions) : false;
      });

      if (connectingMatch) {
        let tries = 0;
        while (tries < 16 && connectingMatch.status === 'connecting') {
          await delay(400);
          const ready = findLiveSocketEntry(userId, preferredSessionId);
          if (ready) return ready;
          tries++;
        }
        const afterWait = findLiveSocketEntry(userId, preferredSessionId);
        if (afterWait) return afterWait;
        if (
          connectingMatch.status === 'connecting' &&
          (reconnectTimers.has(connectingMatch.sessionId) ||
            sessionStartLocks.has(connectingMatch.sessionId) ||
            (connectingMatch.socket &&
              (isSocketTrulyOpen(connectingMatch.socket) ||
                isSocketConnecting(connectingMatch.socket))))
        ) {
          return null;
        }
      }

      // 2. Collect candidate DB sessions owned by this user
      const candidates: Array<{ id: string; phone?: string; userId?: string }> = [];
      const addCandidate = (id?: string, phone?: string, uid?: string) => {
        if (!id) return;
        if (!candidates.some(c => c.id === id)) {
          candidates.push({ id, phone, userId: uid });
        }
      };

      if (preferredSessionId) {
        const prefDb = getSessionById(preferredSessionId);
        if (
          !userId ||
          (prefDb
            ? prefDb.user_id === userId || isSessionOwnedByUserId(prefDb.id, userId)
            : isSessionOwnedByUserId(preferredSessionId, userId))
        ) {
          addCandidate(preferredSessionId, prefDb?.phone_number, prefDb?.user_id || userId);
        }
      }

      const sortedDb = [...userDbSessions]
        .filter(s => !s.expires_at || new Date(s.expires_at).getTime() >= Date.now())
        .sort((a, b) => {
          const scoreStatus = (st?: string) => (st === 'connected' ? 2 : st === 'connecting' ? 1 : 0);
          const statusDiff = scoreStatus(b.status) - scoreStatus(a.status);
          if (statusDiff !== 0) return statusDiff;
          return Number(Boolean(b.is_primary)) - Number(Boolean(a.is_primary));
        });

      for (const s of sortedDb) {
        addCandidate(s.id, s.phone_number, s.user_id || userId);
      }

      // 3. Also inspect registered disk auth folders matching user's DB session phone
      if (userId && fs.existsSync(AUTH_DIR) && sortedDb.length > 0) {
        const targetPhones = new Set(
          sortedDb.map(s => normalizePhoneNumber(s.phone_number || '')).filter(p => p.length >= 8)
        );
        for (const folder of fs.readdirSync(AUTH_DIR)) {
          const summary = readCredsSummary(folder);
          if (!summary.registered) continue;
          if (
            isSessionOwnedByUserId(folder, userId) ||
            (summary.phone && targetPhones.has(summary.phone))
          ) {
            const owner = resolveActiveVerifiedOwner(folder, undefined, summary.phone);
            if (!owner || owner.id === userId) {
              addCandidate(folder, summary.phone, userId);
            }
          }
        }
      }

      // 4. Hydrate from MySQL if needed and wake the session socket on demand (for Blast / API / AI)
      for (const cand of candidates) {
        const candMem = activeSessions.get(cand.id);
        if (
          reconnectTimers.has(cand.id) ||
          sessionStartLocks.has(cand.id) ||
          (candMem &&
            candMem.status === 'connecting' &&
            candMem.socket &&
            (isSocketTrulyOpen(candMem.socket) || isSocketConnecting(candMem.socket)))
        ) {
          continue;
        }

        let hasCreds = hasRegisteredCredsOnDisk(cand.id);
        if (!hasCreds) {
          hasCreds = await hydrateSessionAuthFolderFromMysql(cand.id).catch(() => false);
        }
        if (!hasCreds) continue;

        const state = await getOrStartBaileysSession(cand.id, cand.phone, cand.userId || userId);
        let tries = 0;
        while (tries < 14 && state.status === 'connecting') {
          await delay(400);
          const ready = findLiveSocketEntry(userId, preferredSessionId || cand.id);
          if (ready) {
            const activeMem = activeSessions.get(ready.sessionId);
            if (activeMem) activeMem.lastOutgoingAt = Date.now();
            return ready;
          }
          tries++;
        }
        const finalCheck = findLiveSocketEntry(userId, preferredSessionId || cand.id);
        if (finalCheck) {
          const activeMem = activeSessions.get(finalCheck.sessionId);
          if (activeMem) activeMem.lastOutgoingAt = Date.now();
          return finalCheck;
        }
      }

      return null;
    } finally {
      ensureSessionLocks.delete(lockKey);
    }
  })();

  ensureSessionLocks.set(lockKey, promise);
  return promise;
}

registerConnectedSocketProvider(
  (userId?: string, preferredSessionId?: string) => findLiveSocketEntry(userId, preferredSessionId),
  () =>
    Array.from(activeSessions.values())
      .filter((s) => s.status === 'connected' && s.socket && isSocketTrulyOpen(s.socket))
      .map((s) => ({
        sessionId: s.sessionId,
        userId: s.userId,
        phoneNumber: s.phoneNumber || undefined,
        socket: s.socket
      })),
  ensureConnectedSessionForUser
);

if (!fs.existsSync(AUTH_DIR)) {
  fs.mkdirSync(AUTH_DIR, { recursive: true, mode: 0o700 });
}

export function sanitizeSessionId(rawId: string): string {
  const cleaned = String(rawId || '').trim();
  if (!cleaned || !/^[a-zA-Z0-9_.-]{1,128}$/.test(cleaned) || cleaned.includes('..')) {
    throw new Error('ID sesi WhatsApp tidak valid.');
  }
  return cleaned;
}

const CATALOG_UPLOAD_DIR = path.resolve(process.cwd(), 'uploads', 'catalog');
const SAFE_LOCAL_CATALOG_FILE_RE = /^(?:prod|qris)_[a-f0-9-]+\.(png|jpg|webp|gif)$/i;

function resolveLocalCatalogImageBuffer(url?: string): Buffer | null {
  if (!url) return null;
  let relPath = String(url).trim();
  if (/^https?:\/\//i.test(relPath)) {
    try {
      relPath = new URL(relPath).pathname;
    } catch {
      return null;
    }
  }
  if (!relPath.startsWith('/api/catalog/images/')) return null;
  const filename = path.basename(relPath);
  if (!SAFE_LOCAL_CATALOG_FILE_RE.test(filename)) return null;
  const resolved = path.resolve(CATALOG_UPLOAD_DIR, filename);
  if (!resolved.startsWith(CATALOG_UPLOAD_DIR + path.sep)) return null;
  try {
    if (!fs.existsSync(resolved)) return null;
    const stat = fs.statSync(resolved);
    if (!stat.isFile() || stat.size < 50 || stat.size > 5 * 1024 * 1024) return null;
    return fs.readFileSync(resolved);
  } catch {
    return null;
  }
}

function safeSessionFolderPath(sessionId: string): string | null {
  try {
    const safeId = sanitizeSessionId(sessionId);
    const resolved = path.resolve(AUTH_DIR, safeId);
    if (!resolved.startsWith(AUTH_DIR + path.sep)) return null;
    return resolved;
  } catch {
    return null;
  }
}

function clearSessionTimers(sessionId: string) {
  const b = authBackupTimers.get(sessionId);
  if (b) {
    clearTimeout(b);
    authBackupTimers.delete(sessionId);
  }
  const r = reconnectTimers.get(sessionId);
  if (r) {
    clearTimeout(r);
    reconnectTimers.delete(sessionId);
  }
}

export function isPermanentLogoutCode(statusCode?: number): boolean {
  return statusCode === DisconnectReason.loggedOut || statusCode === 401;
}

export function isRestartRequiredCode(statusCode?: number): boolean {
  return statusCode === DisconnectReason.restartRequired || statusCode === 515;
}

export function computePersistentReconnectDelay(retryCount: number, statusCode?: number): number {
  if (isRestartRequiredCode(statusCode)) {
    return 350;
  }
  if (statusCode === DisconnectReason.connectionReplaced) {
    return 5000 + crypto.randomInt(0, 2000);
  }
  const exp = Math.min(5, Math.max(0, retryCount - 1));
  return Math.min(10000, Math.round(2000 * Math.pow(1.45, exp)));
}

function isRecoverableProtocolCode(statusCode?: number): boolean {
  return (
    statusCode === DisconnectReason.badSession ||
    statusCode === DisconnectReason.multideviceMismatch ||
    statusCode === 405 ||
    statusCode === 411 ||
    statusCode === 500
  );
}

function readCredsSummary(sessionId: string): { registered: boolean; phone: string } {
  try {
    const folder = safeSessionFolderPath(sessionId);
    if (!folder) return { registered: false, phone: '' };
    const credsPath = path.join(folder, 'creds.json');
    if (!fs.existsSync(credsPath)) return { registered: false, phone: '' };
    const parsed = JSON.parse(fs.readFileSync(credsPath, 'utf-8'));
    const meId = parsed?.me?.id ? String(parsed.me.id) : '';
    return {
      registered: Boolean(parsed && (parsed.registered || meId)),
      phone: meId ? normalizePhoneNumber(meId.split('@')[0].split(':')[0]) : ''
    };
  } catch {
    return { registered: false, phone: '' };
  }
}

function getCredsPhoneOnDisk(sessionId: string): string {
  return readCredsSummary(sessionId).phone;
}

function resolveActiveVerifiedOwner(sessionId: string, candidateUserId?: string, candidatePhone?: string) {
  const db = initDbFile();
  const cleanPhone = normalizePhoneNumber(candidatePhone || '');

  if (candidateUserId) {
    const u = getUserById(candidateUserId);
    if (u) return u;
  }

  const dbSess = getSessionById(sessionId);
  if (dbSess?.user_id) {
    const u = getUserById(dbSess.user_id);
    if (u) return u;
  }

  const extractedId = extractUserIdFromSessionId(sessionId, db.users);
  if (extractedId) {
    const u = getUserById(extractedId);
    if (u) return u;
  }

  if (cleanPhone && cleanPhone.length >= 8) {
    const matchedSessionOwner = db.sessions.find(
      s => s.user_id && s.phone_number && normalizePhoneNumber(s.phone_number) === cleanPhone
    );
    if (matchedSessionOwner?.user_id) {
      const u = getUserById(matchedSessionOwner.user_id);
      if (u) return u;
    }

    const matchedU = db.users.find(
      u => u.phone && normalizePhoneNumber(u.phone) === cleanPhone
    );
    if (matchedU) return matchedU;
  }

  return null;
}

function isOwnerActiveAndRegistered(owner: ReturnType<typeof getUserById>): boolean {
  return Boolean(owner && owner.is_active && owner.email_verified);
}

async function flushAuthFolderBackupNow(sessionId: string): Promise<void> {
  if (!sessionId || !isMysqlConfigured()) return;
  const folder = safeSessionFolderPath(sessionId);
  if (!folder) return;
  try {
    if (!hasRegisteredCredsOnDisk(sessionId)) return;
    const dirEntries = await fs.promises.readdir(folder, { withFileTypes: true }).catch(() => null);
    if (!dirEntries) return;
    const files = dirEntries
      .filter(d => d.isFile() && d.name.endsWith('.json'))
      .map(d => d.name)
      .sort();
    const filesMap: Record<string, string> = {};
    const hash = crypto.createHash('sha256');
    for (const file of files) {
      const fp = path.join(folder, file);
      const content = await fs.promises.readFile(fp, 'utf-8');
      filesMap[file] = content;
      hash.update(file).update('\0').update(content).update('\0');
    }
    if (!filesMap['creds.json']) return;
    const digest = hash.digest('hex');
    if (lastAuthBackupHashes.get(sessionId) === digest) {
      return;
    }
    await saveBaileysAuthToMysql(sessionId, filesMap);
    lastAuthBackupHashes.set(sessionId, digest);
    lastAuthBackupAt.set(sessionId, Date.now());
  } catch {
    // Non-blocking backup
  }
}

function scheduleAuthFolderBackup(sessionId: string, immediate = false) {
  if (!sessionId || !isMysqlConfigured()) return;
  const folder = safeSessionFolderPath(sessionId);
  if (!folder) return;

  const prev = authBackupTimers.get(sessionId);
  if (prev) clearTimeout(prev);

  if (immediate) {
    void flushAuthFolderBackupNow(sessionId);
    return;
  }

  const lastAt = lastAuthBackupAt.get(sessionId) || 0;
  const waitMs = Math.max(AUTH_BACKUP_DEBOUNCE_MS, lastAt + AUTH_BACKUP_COOLDOWN_MS - Date.now());

  const timer = setTimeout(() => {
    authBackupTimers.delete(sessionId);
    void flushAuthFolderBackupNow(sessionId);
  }, waitMs);
  timer.unref?.();

  authBackupTimers.set(sessionId, timer);
}

async function hydrateSessionAuthFolderFromMysql(sessionId: string): Promise<boolean> {
  const folder = safeSessionFolderPath(sessionId);
  if (!folder) return false;
  if (hasRegisteredCredsOnDisk(sessionId)) return true;

  try {
    const filesMap = await loadBaileysAuthFromMysql(sessionId);
    if (!filesMap || !filesMap['creds.json']) return false;

    if (!fs.existsSync(folder)) {
      fs.mkdirSync(folder, { recursive: true, mode: 0o700 });
    }
    for (const [filename, content] of Object.entries(filesMap)) {
      const base = path.basename(filename);
      if (base === filename && base.endsWith('.json') && typeof content === 'string') {
        fs.writeFileSync(path.join(folder, base), content, { encoding: 'utf-8', mode: 0o600 });
      }
    }
    return hasRegisteredCredsOnDisk(sessionId);
  } catch {
    return false;
  }
}

// Clean session auth directory safely (with path traversal guard)
export function cleanSessionFolder(folderName: string) {
  const targetFolder = safeSessionFolderPath(folderName);
  if (!targetFolder) return;
  try {
    if (fs.existsSync(targetFolder)) {
      fs.rmSync(targetFolder, { recursive: true, force: true });
      console.log(`[Baileys] Auth folder deleted: ${targetFolder}`);
    }
  } catch (err) {
    console.error(`[Baileys] Error cleaning session folder ${folderName}:`, err);
  }
}

// Helper to attach Auto-Reply, Anti-Ban, Centang Biru, and Quota Deductions to Baileys socket
const commandState = new Map<string, { step: string; data?: any; updatedAt: number }>();
const COMMAND_STATE_TTL_MS = 15 * 60 * 1000;
const processedMessageIds = new Set<string>();
const incomingChatQueues = new Map<string, Promise<void>>();

function enqueueIncomingChatTask(chatKey: string, task: () => Promise<void>): void {
  const prev = incomingChatQueues.get(chatKey) || Promise.resolve();
  const next = prev
    .catch(() => {})
    .then(task)
    .catch(err => {
      console.error(`[Baileys Incoming Queue Error:${chatKey}]`, err);
    })
    .finally(() => {
      if (incomingChatQueues.get(chatKey) === next) {
        incomingChatQueues.delete(chatKey);
      }
    });
  incomingChatQueues.set(chatKey, next);
}

function cleanupExpiredCommandStates(now = Date.now()) {
  if (commandState.size === 0) return;
  for (const [key, entry] of commandState.entries()) {
    if (!entry.updatedAt || now - entry.updatedAt > COMMAND_STATE_TTL_MS) {
      commandState.delete(key);
    }
  }
}

function rememberProcessedMsgId(id?: string | null) {
  if (!id) return;
  processedMessageIds.add(id);
  if (processedMessageIds.size > 500) {
    const first = processedMessageIds.values().next().value;
    if (first) processedMessageIds.delete(first);
  }
}

export function resolveIncomingSenderIdentity(
  sock: any,
  msg: any,
  remoteJid: string
): {
  senderPhone: string;
  cleanSender: string;
  rawRemoteDigits: string;
  isLidThread: boolean;
  fallbackPnJid: string | null;
} {
  const isLidThread = remoteJid.endsWith('@lid');
  const rawRemoteDigits = remoteJid.replace(/@.*/, '').split(':')[0].replace(/\D/g, '');
  const altCandidates = [
    msg?.key?.remoteJidAlt,
    msg?.key?.participantAlt,
    msg?.key?.participant
  ].filter((v): v is string => typeof v === 'string' && v.trim().length > 0);

  let pnJid = altCandidates.find(j => j.endsWith('@s.whatsapp.net') || j.endsWith('@c.us')) || null;

  if (!pnJid && !isLidThread && (remoteJid.endsWith('@s.whatsapp.net') || remoteJid.endsWith('@c.us'))) {
    pnJid = remoteJid;
  }

  // Fallback synchronous cache / lidMapping lookup if Baileys exposes it synchronously or as value
  if (!pnJid && isLidThread && sock?.signalRepository?.lidMapping?.getPNForLID) {
    // Resolved asynchronously when available in caller
  }

  const resolvedPhoneRaw = pnJid
    ? pnJid.replace(/@.*/, '').split(':')[0]
    : remoteJid.replace(/@.*/, '').split(':')[0];
  const senderPhone = normalizePhoneNumber(resolvedPhoneRaw) || resolvedPhoneRaw.replace(/\D/g, '') || resolvedPhoneRaw;
  const cleanSender = senderPhone.replace(/\D/g, '');
  const fallbackPnJid =
    cleanSender.length >= 8 && (!isLidThread || Boolean(pnJid))
      ? `${cleanSender}@s.whatsapp.net`
      : pnJid && pnJid.endsWith('@s.whatsapp.net')
        ? pnJid
        : null;

  return {
    senderPhone,
    cleanSender,
    rawRemoteDigits,
    isLidThread,
    fallbackPnJid
  };
}

/**
 * Reliable, non-duplicating send wrapper that watches WhatsApp server message ACK (`CB:ack`).
 * If WhatsApp server already acknowledged `msgId` while Baileys is still finishing background
 * key-store commit / privacy-token IQs, resolves immediately instead of falsely throwing a timeout
 * or re-sending a duplicate message.
 */
export async function sendSocketMessageWithAckGuard(
  sock: any,
  jid: string,
  content: any,
  options?: {
    timeoutMs?: number;
    fallbackJid?: string | null;
    sessionData?: SessionState | null;
    sendOptions?: Record<string, any>;
  }
): Promise<any> {
  if (!sock || !isSocketTrulyOpen(sock)) {
    throw new Error('Koneksi WebSocket WhatsApp sedang tertutup atau terputus.');
  }

  const timeoutMs = Math.max(8000, options?.timeoutMs ?? 24000);
  const myJid = sock?.authState?.creds?.me?.id || sock?.user?.id || '';
  const msgId =
    (options?.sendOptions?.messageId as string | undefined) ||
    generateMessageIDV2(myJid);

  const attemptSendToJid = async (targetJid: string, useMsgId: string) => {
    const ws = sock?.ws;
    let ackSuccess = false;
    let ackError: string | null = null;
    let resolveAckEarly!: () => void;
    const ackEarlyPromise = new Promise<void>(resolve => {
      resolveAckEarly = resolve;
    });

    const onAck = (ackNode: any) => {
      try {
        const id = String(ackNode?.attrs?.id || '').trim();
        if (!id || id !== useMsgId) return;
        const errCode = ackNode?.attrs?.error ? String(ackNode.attrs.error).trim() : '';
        if (errCode) {
          ackError = errCode;
        } else {
          ackSuccess = true;
          if (options?.sessionData) {
            options.sessionData.lastUpdated = Date.now();
          }
        }
        resolveAckEarly();
      } catch {
        // Ignore ACK parser errors
      }
    };

    if (ws && typeof ws.on === 'function') {
      ws.on('CB:ack,class:message', onAck);
      ws.on('CB:ack', onAck);
    }

    let timeoutTimer: ReturnType<typeof setTimeout> | null = null;
    try {
      const sendPromise = sock.sendMessage(targetJid, content, {
        ...(options?.sendOptions || {}),
        messageId: useMsgId
      });

      // Avoid unhandled rejection if ackEarlyPromise wins first
      sendPromise.catch(() => {});

      const timeoutPromise = new Promise<never>((_, reject) => {
        timeoutTimer = setTimeout(() => {
          reject(
            new Error(
              `Batas waktu pengiriman ke nomor tujuan habis (Timeout ${Math.round(timeoutMs / 1000)}d)`
            )
          );
        }, timeoutMs);
      });

      const ackWinPromise = ackEarlyPromise.then(async () => {
        if (ackError) {
          throw new Error(`Server WhatsApp menolak pesan (ACK error ${ackError}).`);
        }
        // Give Baileys up to 350ms to finish local commitWithRetry cleanly before returning early
        const finished = await Promise.race([
          sendPromise.then((res: any) => ({ done: true, res })).catch(() => ({ done: false, res: null })),
          delay(350).then(() => ({ done: false, res: null }))
        ]);
        return (
          finished.res || {
            key: { id: useMsgId, remoteJid: targetJid, fromMe: true },
            messageTimestamp: Math.floor(Date.now() / 1000),
            ackConfirmedEarly: true
          }
        );
      });

      const res = await Promise.race([sendPromise, ackWinPromise, timeoutPromise]);
      if (options?.sessionData) {
        options.sessionData.lastUpdated = Date.now();
      }
      return res;
    } catch (err: any) {
      if (ackSuccess && !ackError) {
        return {
          key: { id: useMsgId, remoteJid: targetJid, fromMe: true },
          messageTimestamp: Math.floor(Date.now() / 1000),
          ackConfirmedEarly: true
        };
      }
      throw err;
    } finally {
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (ws && typeof ws.off === 'function') {
        ws.off('CB:ack,class:message', onAck);
        ws.off('CB:ack', onAck);
      } else if (ws && typeof ws.removeListener === 'function') {
        ws.removeListener('CB:ack,class:message', onAck);
        ws.removeListener('CB:ack', onAck);
      }
    }
  };

  try {
    return await attemptSendToJid(jid, msgId);
  } catch (err: any) {
    const altJid = options?.fallbackJid;
    if (altJid && altJid !== jid && isSocketTrulyOpen(sock)) {
      const retryId = generateMessageIDV2(myJid);
      return await attemptSendToJid(altJid, retryId);
    }
    throw err;
  }
}

// Parse /send and /broadcast arguments in flexible single or multi-recipient formats:
// 1) /send 08123456789 Halo kak
// 2) /broadcast 08123456789, 08198765432, 08571234567 Halo kak promo spesial!
// 3) Multiline phone list followed by shared message
// 4) Multiline where each line has <nomor> <pesan>
export function parseSendOrBroadcastTasks(rawArgs: string): Array<{ targetPhone: string; messageToSend: string }> {
  const cleanedInput = rawArgs.replace(/^\/(?:send|broadcast|kirim|kirimpesan)\b\s*/i, '').trim();
  if (!cleanedInput) return [];

  // Check if input has multiple lines where EACH line is a distinct "<phone> <message>" task
  const nonEmptyLines = cleanedInput
    .split(/\r?\n/)
    .map(l => l.replace(/^\/(?:send|broadcast|kirim|kirimpesan)\b\s*/i, '').trim())
    .filter(Boolean);

  if (nonEmptyLines.length > 1) {
    const perLineTasks: Array<{ targetPhone: string; messageToSend: string }> = [];
    let allLinesHaveOwnMsg = true;

    for (const line of nonEmptyLines) {
      const m = line.match(/^(\+?[0-9][0-9\-()]{7,15})\s*[:|\-]?\s+(.+)$/);
      if (m) {
        const digits = m[1].replace(/\D/g, '');
        const msg = m[2].trim();
        // Make sure the message part is not just another bare phone number
        const msgDigitsOnly = msg.replace(/[\s,;+\-()]/g, '');
        const looksLikePhoneList = /^[0-9]+$/.test(msgDigitsOnly) && msgDigitsOnly.length >= 8;
        if (digits.length >= 8 && digits.length <= 16 && msg && !looksLikePhoneList) {
          perLineTasks.push({ targetPhone: digits, messageToSend: msg });
        } else {
          allLinesHaveOwnMsg = false;
          break;
        }
      } else {
        allLinesHaveOwnMsg = false;
        break;
      }
    }

    if (allLinesHaveOwnMsg && perLineTasks.length > 1) {
      return perLineTasks;
    }
  }

  // 1. Key-value format: to=0812xxx,0819xxx text=Halo or to=0812xxx msg=Halo
  const kvMatch = cleanedInput.match(/^to=([^\s&]+)[,\s&]+(?:text|msg|pesan)=([\s\S]+)$/i);
  if (kvMatch) {
    const phones = kvMatch[1]
      .split(/[,;]+/)
      .map(p => p.replace(/\D/g, ''))
      .filter(p => p.length >= 8 && p.length <= 16);
    const msg = kvMatch[2].trim();
    if (phones.length > 0 && msg) {
      return Array.from(new Set(phones)).map(targetPhone => ({ targetPhone, messageToSend: msg }));
    }
  }

  // 2. Pipe format: 0812xxx, 0819xxx | Halo kak
  if (cleanedInput.includes('|')) {
    const pipeIdx = cleanedInput.indexOf('|');
    const phoneSection = cleanedInput.substring(0, pipeIdx);
    const msgPart = cleanedInput.substring(pipeIdx + 1).trim();
    const phones = phoneSection
      .split(/[\s,;]+/)
      .map(p => p.replace(/\D/g, ''))
      .filter(p => p.length >= 8 && p.length <= 16);
    if (phones.length > 0 && msgPart) {
      return Array.from(new Set(phones)).map(targetPhone => ({ targetPhone, messageToSend: msgPart }));
    }
  }

  // 3. Scan 1 or many leading phone numbers (separated by comma, semicolon, space, or newline) followed by shared message
  const phones: string[] = [];
  let pos = 0;
  while (pos < cleanedInput.length) {
    const wsMatch = cleanedInput.slice(pos).match(/^[\s,;]+/);
    if (wsMatch) pos += wsMatch[0].length;
    const tokMatch = cleanedInput.slice(pos).match(/^([^\s]+)/);
    if (!tokMatch) break;
    const token = tokMatch[1];
    const subParts = token.split(/[,;]+/).filter(Boolean);
    const isAllPhones =
      subParts.length > 0 &&
      subParts.every(sp => {
        const digits = sp.replace(/\D/g, '');
        return /^[\d+\-()]+$/.test(sp) && digits.length >= 8 && digits.length <= 16;
      });
    if (isAllPhones) {
      subParts.forEach(sp => phones.push(sp.replace(/\D/g, '')));
      pos += token.length;
    } else {
      break;
    }
  }

  if (phones.length > 0) {
    const msgPart = cleanedInput.slice(pos).replace(/^[\s:,\-|]+/, '').trim();
    if (msgPart) {
      return Array.from(new Set(phones)).map(targetPhone => ({ targetPhone, messageToSend: msgPart }));
    }
  }

  // 4. Phone number with spaces/dashes e.g. +62 812-3456-7890 Halo kak
  const flexMatch = cleanedInput.match(/^(\+?[0-9][0-9\-\s]{7,17}?)\s+([\s\S]+)$/);
  if (flexMatch) {
    const digits = flexMatch[1].replace(/\D/g, '');
    if (digits.length >= 8 && digits.length <= 16 && flexMatch[2].trim()) {
      return [{ targetPhone: digits, messageToSend: flexMatch[2].trim() }];
    }
  }

  return [];
}

function parseSendCommandArgs(rawArgs: string): { targetPhone: string; messageToSend: string } {
  const tasks = parseSendOrBroadcastTasks(rawArgs);
  if (tasks.length > 0) {
    return tasks[0];
  }
  return { targetPhone: '', messageToSend: '' };
}

// Anti-Echo Loop Breaker: tracks texts sent recently by the bot to prevent self-reflection infinite loops
const recentBotOutgoingTexts = new Map<string, number>();

function recordBotOutgoing(text: string) {
  if (!text) return;
  const key = text.trim();
  recentBotOutgoingTexts.set(key, Date.now());
  if (recentBotOutgoingTexts.size > 300) {
    const now = Date.now();
    for (const [k, time] of recentBotOutgoingTexts.entries()) {
      if (now - time > 45000) recentBotOutgoingTexts.delete(k);
    }
  }
}

function isRecentBotOutgoing(text: string): boolean {
  if (!text) return false;
  const key = text.trim();
  const time = recentBotOutgoingTexts.get(key);
  if (time && (Date.now() - time < 45000)) {
    return true;
  }
  return false;
}

export function attachSocketMessageListener(sock: any, sessionId: string, sessionData: any) {
  sessionData.detachRawHandlers?.();
  sessionData.detachRawHandlers = attachMetaAiRawSocketHandlers(sock, sessionId);

  sock.ev.on('messages.update', (updates: any[]) => {
    sessionData.lastUpdated = Date.now();
    try {
      handleMetaAiIncomingUpdate(sessionId, updates);
    } catch (err) {
      console.warn('[Baileys Meta AI Update Error]', err);
    }
  });

  const handleSingleIncomingMessage = async (mType: string, msg: any) => {
    if (!msg?.message) return;
    sessionData.lastUpdated = Date.now();
    if (msg.key?.id) {
      rememberProtoMessage(msg.key, msg.message);
    }

    const remoteJid = msg.key?.remoteJid || msg.message?.deviceSentMessage?.destinationJid;
    if (!remoteJid) return;

    // Intercept Meta AI contact messages/replies (by JID, remoteJidAlt, or learned session LID) BEFORE other filters
    if (handleMetaAiIncomingUpsert(sessionId, msg)) {
      return;
    }

    if (
      remoteJid.endsWith('@g.us') ||
      remoteJid === 'status@broadcast' ||
      remoteJid.endsWith('@broadcast') ||
      remoteJid.endsWith('@newsletter')
    ) {
      return; // 1-on-1 chats only
    }

    const msgId = msg.key?.id;
    if (msgId && processedMessageIds.has(msgId)) return;

    // Ignore old history sync on 'append' events (only allow fresh messages <= 45s old)
    if (mType === 'append') {
      const rawTs = typeof msg.messageTimestamp === 'number'
        ? msg.messageTimestamp
        : Number(msg.messageTimestamp?.low || msg.messageTimestamp || 0);
      if (rawTs > 0 && Math.floor(Date.now() / 1000) - rawTs > 45) {
        return;
      }
    }

    // Unwrap nested WhatsApp Multi-Device containers (deviceSentMessage for self-chat, ephemeralMessage, viewOnce)
    const innerMsg =
      msg.message?.deviceSentMessage?.message ||
      msg.message?.ephemeralMessage?.message ||
      msg.message?.viewOnceMessage?.message ||
      msg.message?.viewOnceMessageV2?.message ||
      msg.message?.documentWithCaptionMessage?.message ||
      msg.message;

    const hasMediaAttachment = Boolean(
      innerMsg?.imageMessage ||
      innerMsg?.documentMessage ||
      msg.message?.imageMessage ||
      msg.message?.documentMessage
    );

    const rawMessageText = (
      innerMsg?.conversation ||
      innerMsg?.extendedTextMessage?.text ||
      innerMsg?.imageMessage?.caption ||
      innerMsg?.videoMessage?.caption ||
      innerMsg?.documentMessage?.caption ||
      msg.message?.conversation ||
      msg.message?.extendedTextMessage?.text ||
      ''
    ).trim();

    if (!rawMessageText && (!hasMediaAttachment || msg.key.fromMe)) return;

    const messageText = rawMessageText || '[Pelanggan mengirim lampiran gambar/dokumen bukti pembayaran]';

    // Anti-Echo loop breaker: ignore messages that match recent bot outgoing messages
    if (rawMessageText && isRecentBotOutgoing(rawMessageText)) {
      console.log(`[Baileys Anti-Echo] Discarding reflected message from bot's own output to prevent loop: "${rawMessageText.substring(0, 30)}..."`);
      return;
    }

    cleanupExpiredCommandStates();

    let identity = resolveIncomingSenderIdentity(sock, msg, remoteJid);
    // In Baileys v7, incoming DMs may use @lid without remoteJidAlt populated in key — look up real PN via Signal LID map
    if (identity.isLidThread && !identity.fallbackPnJid && typeof sock?.signalRepository?.lidMapping?.getPNForLID === 'function') {
      try {
        const mappedPn = await Promise.race([
          sock.signalRepository.lidMapping.getPNForLID(remoteJid),
          new Promise<null>(resolve => setTimeout(() => resolve(null), 1500))
        ]);
        if (typeof mappedPn === 'string' && mappedPn.trim()) {
          const cleanMapped = mappedPn.trim().replace(/@.*/, '').split(':')[0];
          const normMapped = normalizePhoneNumber(cleanMapped) || cleanMapped.replace(/\D/g, '');
          if (normMapped.length >= 8) {
            identity = {
              senderPhone: normMapped,
              cleanSender: normMapped,
              rawRemoteDigits: identity.rawRemoteDigits,
              isLidThread: true,
              fallbackPnJid: `${normMapped}@s.whatsapp.net`
            };
          }
        }
      } catch {
        // Keep fallback identity
      }
    }

    const { senderPhone, cleanSender, rawRemoteDigits, isLidThread, fallbackPnJid } = identity;
    const replyTargetJid = remoteJid;
    const senderName = msg.pushName || 'Pengguna WhatsApp';
    const trimmedMsg = messageText.trim();
    const stateKey = `${sessionId}:${remoteJid}`;
    const hasActiveDialog = commandState.has(stateKey) || commandState.has(senderPhone) || commandState.has(remoteJid);
    const isSlashCommand = trimmedMsg.startsWith('/');

    // When msg.key.fromMe is true (sent from the connected phone itself / self-chat):
    // ONLY allow if it is an explicit '/' command (like /send, /status, /help, /batal) OR an active /send step-2 reply.
    // Ignore all normal outgoing messages so personal notes & chats to customers never trigger auto-reply or loop!
    if (msg.key.fromMe && !isSlashCommand && !hasActiveDialog) {
      return;
    }

    rememberProcessedMsgId(msgId);
    console.log(`[Baileys Incoming] Session=${sessionId} From=${senderPhone} (${senderName}) jid=${remoteJid} fromMe=${Boolean(msg.key.fromMe)} media=${hasMediaAttachment}: "${messageText}"`);

    const db = initDbFile();
    const cleanConnected = normalizePhoneNumber(sessionData.phoneNumber || '');
    const sockPhone = normalizePhoneNumber(sock.user?.id ? sock.user.id.split('@')[0].split(':')[0] : '');
    const sockLid = sock.user?.lid ? sock.user.lid.split('@')[0].split(':')[0].replace(/\D/g, '') : '';

    // Strict exact check ONLY against this connected device (prevents false positives & stops owner/allowed normal chats from being ignored)
    const isSelf = Boolean(
      msg.key.fromMe ||
      (cleanSender && cleanConnected && cleanSender === cleanConnected) ||
      (cleanSender && sockPhone && cleanSender === sockPhone) ||
      (sockLid && ((isLidThread && rawRemoteDigits === sockLid) || cleanSender === sockLid))
    );

    const matchedSessionBySender = db.sessions.find(s => {
      if (!s.phone_number || !cleanSender) return false;
      const sp = normalizePhoneNumber(s.phone_number);
      return sp.length >= 8 && sp === cleanSender;
    });

    const user =
      db.users.find(u => {
        if (!u.phone || !cleanSender) return false;
        const p = normalizePhoneNumber(u.phone);
        return p.length >= 8 && p === cleanSender;
      }) ||
      (matchedSessionBySender?.user_id ? getUserById(matchedSessionBySender.user_id) : null) ||
      (sessionData.userId ? getUserById(sessionData.userId) : null);

    const isOwner = Boolean(
      user?.phone && cleanSender && normalizePhoneNumber(user.phone) === cleanSender
    );
    const isAllowed = Boolean(
      user?.allowed_numbers &&
      cleanSender &&
      user.allowed_numbers.some(n => {
        const norm = normalizePhoneNumber(n);
        return norm.length >= 8 && norm === cleanSender;
      })
    );

    // =========================================================================
    // REMOTE COMMAND BRIDGE & SELF-CHAT LOOP PREVENTION GUARD
    // Remote commands (/send, /status, /help, /batal) work for Self/Owner/Allowed,
    // while normal chats from Owner/Allowed (non-self) STILL trigger Auto-Reply & Meta AI!
    // =========================================================================
    if ((isSlashCommand || hasActiveDialog) && (isSelf || isOwner || isAllowed)) {
      const clearSenderDialogState = () => {
        commandState.delete(stateKey);
        commandState.delete(senderPhone);
        commandState.delete(remoteJid);
      };

      const sendCommandReply = async (replyBody: string) => {
        recordBotOutgoing(replyBody);
        await sendSocketMessageWithAckGuard(
          sock,
          replyTargetJid,
          { text: replyBody },
          { timeoutMs: 18000, fallbackJid: fallbackPnJid, sessionData }
        );
      };

      const resolveOutboundSocket = () => {
        if (user) {
          const userSessions = Array.from(activeSessions.values()).filter(
            s => s.userId === user.id && s.status === 'connected' && s.socket && isSocketTrulyOpen(s.socket)
          );
          const primaryUserSession = userSessions.find(s => s.is_primary) || userSessions[0];
          if (primaryUserSession?.socket) return primaryUserSession.socket;
        }
        return sock;
      };

      const executeSendOrBroadcastTasks = async (tasks: Array<{ targetPhone: string; messageToSend: string }>) => {
        const sockToUse = resolveOutboundSocket();

        if (tasks.length === 1) {
          const { targetPhone, messageToSend } = tasks[0];
          if (user) {
            const quota = deductUserDailyQuota(user.id);
            if (!quota.allowed) {
              const quotaMsg = `❌ *Gagal Kirim:* ${quota.message || 'Batas kuota harian Anda telah habis.'}`;
              await sendCommandReply(quotaMsg);
              return;
            }
          }

          const cleanTarget = normalizePhoneNumber(targetPhone);
          const targetJid = `${cleanTarget}@s.whatsapp.net`;
          try {
            recordBotOutgoing(messageToSend);
            await sendSocketMessageWithAckGuard(
              sockToUse,
              targetJid,
              { text: messageToSend },
              { timeoutMs: 22000, sessionData }
            );

            addMessageLog({
              wam_id: `cmd_out_${Date.now()}`,
              session_id: sessionId,
              user_id: user?.id || sessionData.userId,
              sender_phone: cleanTarget,
              sender_name: `Tujuan (${cleanTarget})`,
              message_body: messageToSend,
              direction: 'outgoing',
              status: 'Sukses',
              reply_body: 'Dikirim via Remote WhatsApp Command (/send)'
            });

            const successReply =
              `✅ *Pesan Berhasil Terkirim!*\n\n` +
              `• Nomor Tujuan: *${cleanTarget}*\n` +
              `• Isi Pesan: "${messageToSend}"\n` +
              `• Via Gateway: *${sessionData.phoneNumber || sockPhone || 'Japriin'}*`;
            await sendCommandReply(successReply);
          } catch (sendErr: any) {
            const errMsg = `❌ *Gagal mengirim pesan ke ${cleanTarget}:* ${sendErr?.message || 'Error koneksi gateway'}`;
            await sendCommandReply(errMsg);
          }
          return;
        }

        const startNotice =
          `⏳ *Memproses Broadcast ke ${tasks.length} Nomor...*\n` +
          `Mohon tunggu, pesan sedang dikirim bertahap dengan proteksi Anti-Ban Guard.`;
        await sendCommandReply(startNotice);

        let successCount = 0;
        let failedCount = 0;
        const successPhones: string[] = [];

        for (let i = 0; i < tasks.length; i++) {
          const { targetPhone, messageToSend } = tasks[i];
          const cleanTarget = normalizePhoneNumber(targetPhone);
          if (!cleanTarget || cleanTarget.length < 8) {
            failedCount++;
            continue;
          }

          if (user) {
            const quota = deductUserDailyQuota(user.id);
            if (!quota.allowed) {
              failedCount++;
              continue;
            }
          }

          const targetJid = `${cleanTarget}@s.whatsapp.net`;
          try {
            recordBotOutgoing(messageToSend);
            await sendSocketMessageWithAckGuard(
              sockToUse,
              targetJid,
              { text: messageToSend },
              { timeoutMs: 22000, sessionData }
            );

            successCount++;
            successPhones.push(cleanTarget);
            addMessageLog({
              wam_id: `bc_cmd_${Date.now()}_${i}`,
              session_id: sessionId,
              user_id: user?.id || sessionData.userId,
              sender_phone: cleanTarget,
              sender_name: `Broadcast (${cleanTarget})`,
              message_body: messageToSend,
              direction: 'outgoing',
              status: 'Sukses',
              reply_body: 'Dikirim via Broadcast WhatsApp (/broadcast)'
            });
          } catch (err: any) {
            failedCount++;
            addMessageLog({
              wam_id: `bc_fail_${Date.now()}_${i}`,
              session_id: sessionId,
              user_id: user?.id || sessionData.userId,
              sender_phone: cleanTarget,
              sender_name: `Broadcast (${cleanTarget})`,
              message_body: messageToSend,
              direction: 'outgoing',
              status: 'Gagal',
              error_detail: err?.message || 'Gagal kirim broadcast'
            });
          }

          if (i < tasks.length - 1) {
            await delay(1000 + Math.floor(Math.random() * 800));
          }
        }

        addBroadcastHistory({
          user_id: user?.id || sessionData.userId,
          session_id: sessionId,
          recipients_count: tasks.length,
          message: tasks[0]?.messageToSend || 'Broadcast Multi-Pesan',
          status: failedCount === tasks.length ? 'failed' : 'completed',
          success_count: successCount,
          failed_count: failedCount
        });

        const summaryReply =
          `✅ *Broadcast Selesai Diproses!*\n\n` +
          `• Total Tujuan: *${tasks.length} Nomor*\n` +
          `• Berhasil Terkirim: *${successCount} Nomor*\n` +
          `• Gagal: *${failedCount} Nomor*\n` +
          (successPhones.length > 0
            ? `• Penerima: *${successPhones.slice(0, 6).join(', ')}${successPhones.length > 6 ? ` (+${successPhones.length - 6} lainnya)` : ''}*\n`
            : '') +
          `• Via Gateway: *${sessionData.phoneNumber || sockPhone || 'Japriin'}*\n` +
          `• Log Retensi: *Otomatis dihapus setelah 7 hari*`;
        await sendCommandReply(summaryReply);
      };

      if (isSlashCommand) {
        const parts = trimmedMsg.split(/\s+/);
        const cmd = parts[0].toLowerCase();

        if (cmd === '/batal' || cmd === '/cancel') {
          clearSenderDialogState();
          await sendCommandReply(`✓ *Perintah interaktif telah dibatalkan.*`);
          return;
        }

        if (cmd === '/status' || cmd === '/saldo' || cmd === '/kuota' || cmd === '/cekkuota' || cmd === '/statusbot') {
          const u = user || (sessionData.userId ? getUserById(sessionData.userId) : null);
          const plan = db.plans.find(p => p.id === u?.plan_id) || db.plans[0];
          const usedToday = u?.daily_messages_sent || 0;
          const remainingToday = Math.max(0, (plan?.daily_msg_limit || 100) - usedToday);
          const statusReply =
            `📊 *Status Japriin Gateway*\n\n` +
            `• Akun: *${u?.name || 'Operator'}* (@${u?.username || 'user'})\n` +
            `• Paket: *${plan?.name || 'Pro'}*\n` +
            `• Nomor Gateway: *${sessionData.phoneNumber || sockPhone || 'Terhubung'}*\n` +
            `• Sisa Kuota Hari Ini: *${remainingToday} / ${plan?.daily_msg_limit || 100} pesan*\n` +
            `• Status Gateway: *TERHUBUNG (Anti-Ban Guard Aktif)*\n\n` +
            `_Ketik */send* untuk mengirim pesan ke nomor tujuan._`;
          await sendCommandReply(statusReply);
          return;
        }

        if (cmd === '/help' || cmd === '/bantuan' || cmd === '/menu') {
          const helpReply =
            `🤖 *Panduan Japriin Remote Command Bridge*\n\n` +
            `Anda dapat mengirim pesan dari Nomor Sistem maupun Nomor Sendiri dengan perintah berikut:\n\n` +
            `1️⃣ */send*\n` +
            `   Membuka template interaktif kirim pesan.\n\n` +
            `2️⃣ */send <nomor_tujuan> <isi_pesan>*\n` +
            `   Kirim pesan langsung dalam 1 langkah.\n` +
            `   _Contoh: /send 08123456789 Halo kak, pesanan sudah dikirim._\n\n` +
            `3️⃣ */status* atau */kuota*\n` +
            `   Cek sisa kuota harian & status koneksi bot.\n\n` +
            `4️⃣ */batal*\n` +
            `   Batalkan dialog kirim pesan yang sedang aktif.\n\n` +
            `💡 _Standar Anti-Loop: Chat biasa tanpa awalan / ke nomor sendiri otomatis diabaikan agar tidak memicu balasan berulang (looping)._`;
          await sendCommandReply(helpReply);
          return;
        }

        if (cmd === '/send' || cmd === '/broadcast' || cmd === '/kirim' || cmd === '/kirimpesan') {
          const fullArgs = trimmedMsg.substring(cmd.length).trim();
          const tasks = parseSendOrBroadcastTasks(fullArgs);

          if (tasks.length > 0) {
            clearSenderDialogState();
            await executeSendOrBroadcastTasks(tasks);
            return;
          }

          const nowTs = Date.now();
          commandState.set(stateKey, { step: 'awaiting_direct_target', updatedAt: nowTs });
          commandState.set(senderPhone, { step: 'awaiting_direct_target', updatedAt: nowTs });
          const promptMsg =
            `📱 *Template Kirim Pesan & Broadcast (Japriin Bridge)*\n\n` +
            `Silakan balas pesan ini dengan salah satu format berikut:\n\n` +
            `1️⃣ *Kirim ke 1 Nomor:*\n` +
            `*08123456789 Halo kak, pesanan Anda sudah siap dikirim.*\n\n` +
            `2️⃣ *Broadcast ke Banyak Nomor (1 Pesan Sama):*\n` +
            `*08123456789, 08198765432, 08571234567 Halo kak, promo spesial hari ini!*\n` +
            `_(Nomor juga bisa disusun per baris baru lalu diikuti isi pesan di bawahnya)_\n\n` +
            `3️⃣ *Broadcast Banyak Pesan Berbeda (Per Baris):*\n` +
            `*08123456789 Halo kak Budi, pesanan siap*\n` +
            `*08198765432 Halo kak Ani, pesanan dikirim*\n\n` +
            `_Ketik */batal* untuk membatalkan pengiriman._`;
          await sendCommandReply(promptMsg);
          return;
        }

        const unknownCmdReply =
          `ℹ️ Perintah *${cmd}* tidak dikenali.\n\n` +
          `Gunakan perintah standar berikut:\n` +
          `• */send* — Template kirim pesan / broadcast\n` +
          `• */send <nomor> <pesan>* — Kirim pesan langsung\n` +
          `• */broadcast <nomor1>,<nomor2> <pesan>* — Broadcast banyak nomor\n` +
          `• */status* — Cek kuota & status gateway\n` +
          `• */help* — Panduan lengkap`;
        await sendCommandReply(unknownCmdReply);
        return;
      }

      const activeState = commandState.get(stateKey) || commandState.get(senderPhone) || commandState.get(remoteJid);
      if (activeState && activeState.step === 'awaiting_direct_target') {
        const tasks = parseSendOrBroadcastTasks(trimmedMsg);
        if (tasks.length > 0) {
          clearSenderDialogState();
          await executeSendOrBroadcastTasks(tasks);
          return;
        }
        const helpFormat =
          `⚠️ *Format Pengiriman Belum Sesuai*\n\n` +
          `Silakan kirim dengan format:\n` +
          `👉 *<nomor_tujuan> <isi_pesan>*\n` +
          `👉 *<nomor1>, <nomor2>, <nomor3> <isi_pesan>*\n\n` +
          `Contoh:\n` +
          `*08123456789 Halo Kak, pesanan sudah dikirim*\n\n` +
          `_Atau ketik */batal* untuk keluar dari mode kirim pesan._`;
        await sendCommandReply(helpFormat);
        return;
      }
    }

    // Suppress ONLY true self-chat (connected device itself / fromMe) non-slash messages to prevent infinite loops
    if (isSelf) {
      console.log(`[Baileys Self-Chat Ignored] Pesan dari perangkat sendiri (${senderPhone}) bukan perintah '/'. Dilewati.`);
      return;
    }

    // 2. Get session owner information for multi-user isolation & quota checking
    let dbSession = getSessionById(sessionId);
    if (!dbSession && sessionData.phoneNumber) {
      const cleanSessionPhone = normalizePhoneNumber(sessionData.phoneNumber);
      dbSession = db.sessions.find(s => s.phone_number && normalizePhoneNumber(s.phone_number) === cleanSessionPhone) || null;
    }

    let sessionUserId = dbSession?.user_id || sessionData.userId;
    if (!sessionUserId && sessionData.phoneNumber) {
      const cleanPhone = normalizePhoneNumber(sessionData.phoneNumber);
      const matchedUser = db.users.find(u => u.phone && normalizePhoneNumber(u.phone) === cleanPhone);
      if (matchedUser) sessionUserId = matchedUser.id;
    }
    if (!sessionUserId) {
      sessionUserId = extractUserIdFromSessionId(sessionId, db.users);
    }

    if (dbSession && sessionUserId && !dbSession.user_id) {
      dbSession.user_id = sessionUserId;
      updateSession(dbSession.id, { user_id: sessionUserId });
    }

    const sessionUser = sessionUserId ? getUserById(sessionUserId) : null;
    if (!isOwnerActiveAndRegistered(sessionUser)) {
      console.warn(`[Baileys Security] Session ${sessionId} has no active registered user. Purging session.`);
      purgeBaileysSessionCompletely(sessionId, sessionData.phoneNumber || undefined).catch(() => {});
      return;
    }

    const autoReplyStatus = getUserAutoReplyStatus(sessionUser);
    if (!autoReplyStatus.allowed) {
      const gateReason = autoReplyStatus.reason || 'Respon pesan otomatis sedang nonaktif.';
      recordAiAuditEvent({
        level: 'WARN',
        stage: 'auto_reply_gate',
        session_id: sessionId,
        user_id: sessionUser!.id,
        senderPhone,
        error_code: autoReplyStatus.expired ? 'FREE_TRIAL_EXPIRED' : 'AUTO_REPLY_DISABLED',
        reason: gateReason
      });
      addMessageLog({
        wam_id: msg.key.id || `baileys_in_${Date.now()}`,
        user_id: sessionUser!.id,
        session_id: sessionId,
        sender_phone: senderPhone,
        sender_name: senderName,
        message_body: messageText,
        direction: 'incoming',
        status: 'Diterima',
        reply_body: gateReason,
        error_detail: `[Auto-Reply Nonaktif] ${gateReason}`,
        ai_generated: false
      });
      return;
    }

    const antiBan = getAntiBanSettings();

    let replyText = '';
    let isAi = false;
    let aiDiagnosticReason: string | undefined;
    let sendQrisImage = false;
    let qrisImageUrl: string | undefined;
    let qrisPublicUrl: string | undefined;
    let orderPaidVerified = false;
    let currentOrderFlow: ReturnType<typeof prepareOrderFlowForIncomingMessage> | null = null;
    let currentActiveCatalog: ReturnType<typeof getActiveCatalogForAi> | null = null;

    const resolvedOwnerId = sessionUser?.id || sessionUserId;
    const scopeId = resolvedOwnerId || sessionId;

    const sysConfig = getSystemConfig();
    const effectiveAi = resolveEffectiveSessionAiSettings({
      user: sessionUser,
      session: dbSession,
      sysConfig
    });
    const userPersonalPrompt = effectiveAi.systemPrompt;
    const canUseAi = effectiveAi.aiEnabled;

    const activeCatalog = getActiveCatalogForAi(resolvedOwnerId);
    currentActiveCatalog = activeCatalog;
    const orderFlow = prepareOrderFlowForIncomingMessage({
      scopeId,
      senderPhone,
      messageText,
      catalog: activeCatalog,
      hasMediaAttachment
    });
    currentOrderFlow = orderFlow;
    const priorHistory = orderFlow.context.history.slice(-6).map(h => ({ role: h.role, text: h.text }));
    recordCustomerTurn(scopeId, senderPhone, 'customer', messageText);

    if (orderFlow.directReply) {
      replyText = orderFlow.directReply.text;
      sendQrisImage = orderFlow.directReply.sendQrisImage;
      qrisImageUrl = orderFlow.directReply.qrisImageUrl;
      qrisPublicUrl = orderFlow.directReply.qrisPublicUrl;
      isAi = false;
      console.log(
        `[Baileys Order System] Fast-path "${orderFlow.directReply.reason}" untuk ${orderFlow.context.customerCode} (QRIS=${sendQrisImage})`
      );
    } else {
      const aiQuotaCheck: ReturnType<typeof canUseAiQuota> = sessionUser
        ? canUseAiQuota(sessionUser.id)
        : {
            allowed: true,
            remainingDaily: 999999,
            dailyLimit: 999999,
            remainingMonthly: 999999,
            monthlyLimit: 999999
          };

      if (canUseAi && aiQuotaCheck.allowed) {
        try {
          console.log(
            `[Baileys Meta AI] Forwarding ${orderFlow.context.customerCode} via session ${sessionId} (catalog=${activeCatalog.enabled ? `${activeCatalog.products.length} produk` : 'off'})...`
          );
          const aiRes = await askMetaAiViaBaileys({
            userId: resolvedOwnerId,
            sessionId,
            senderPhone,
            senderName,
            messageBody: messageText,
            customSystemPrompt: userPersonalPrompt,
            catalogShopName: activeCatalog.shopName,
            catalogProducts: activeCatalog.enabled ? activeCatalog.products : undefined,
            customerCode: orderFlow.context.customerCode,
            customerHistory: priorHistory,
            orderSummary: orderFlow.orderSummaryForPrompt || undefined,
            paymentSummary: orderFlow.paymentSummaryForPrompt || undefined
          });
          if (aiRes.usedAi && aiRes.replyText) {
            const directive = parseAndHandleAiPaymentDirectives(aiRes.replyText, activeCatalog, {
              customerContext: orderFlow.context,
              isPaymentSubmission: orderFlow.isPaymentSubmission
            });
            replyText = directive.cleanText;
            sendQrisImage = directive.sendQrisImage;
            qrisImageUrl = directive.qrisImageUrl;
            qrisPublicUrl = directive.qrisPublicUrl;
            orderPaidVerified = directive.orderPaidVerified;
            isAi = true;
            if (sessionUser && sessionData.phoneNumber && !isPhoneMetaAiVerifiedForUser(sessionUser, sessionData.phoneNumber)) {
              markUserMetaAiVerified(sessionUser.id, sessionData.phoneNumber);
            }
          } else if (aiRes.errorReason) {
            aiDiagnosticReason = `[Meta AI] ${aiRes.errorReason}`;
            console.log(`[Baileys Meta AI Fallback] ${aiRes.errorReason}`);
          }
        } catch (aiErr: any) {
          const msgErr = aiErr?.message || 'Error internal saat memanggil Meta AI.';
          aiDiagnosticReason = `[Meta AI Exception] ${msgErr}`;
          recordAiAuditEvent({
            level: 'ERROR',
            stage: 'meta_ai_reply',
            session_id: sessionId,
            user_id: resolvedOwnerId,
            customer_code: orderFlow.context.customerCode,
            senderPhone,
            error_code: 'BAILEYS_AI_EXCEPTION',
            reason: msgErr
          });
          console.error('[Baileys Meta AI Reply Error]', aiErr);
        }
      } else if (!canUseAi) {
        const disabledReason =
          dbSession?.ai_enabled === false
            ? 'Sakelar Meta AI pada perangkat WhatsApp ini sedang nonaktif.'
            : sessionUser?.role === 'admin'
              ? 'Sakelar Meta AI pada pengaturan sistem sedang nonaktif.'
              : 'Sakelar Meta AI pada akun pengguna sedang nonaktif.';
        aiDiagnosticReason = `[Meta AI Nonaktif] ${disabledReason}`;
        recordAiAuditEvent({
          level: 'WARN',
          stage: 'ai_gate',
          session_id: sessionId,
          user_id: resolvedOwnerId,
          customer_code: orderFlow.context.customerCode,
          senderPhone,
          error_code: 'AI_DISABLED',
          reason: disabledReason
        });
      } else if (canUseAi && !aiQuotaCheck.allowed) {
        const quotaReason = aiQuotaCheck.message || 'Kuota balasan Meta AI harian/bulanan habis.';
        aiDiagnosticReason = `[Kuota AI Habis] ${quotaReason}`;
        recordAiAuditEvent({
          level: 'WARN',
          stage: 'quota_gate',
          session_id: sessionId,
          user_id: resolvedOwnerId,
          customer_code: orderFlow.context.customerCode,
          senderPhone,
          error_code: 'AI_QUOTA_EXCEEDED',
          reason: quotaReason
        });
        console.log(`[Baileys Meta AI Quota] User ${sessionUser?.username} kuota AI habis (${aiQuotaCheck.message}). Beralih ke pesan offline.`);
      }

      if (!replyText && orderFlow.context.cart.length > 0) {
        const deterministicOrderReply = buildDeterministicOrderFallbackReply({
          context: orderFlow.context,
          catalog: activeCatalog,
          messageText,
          isPaymentSubmission: orderFlow.isPaymentSubmission
        });
        if (deterministicOrderReply) {
          replyText = deterministicOrderReply;
        }
      }

      // Send user's default CS reply fallback only when explicitly enabled
      if (!replyText) {
        const isCsEnabled = sessionUser
          ? (sessionUser.role === 'admin' ? sessionUser.default_cs_reply_enabled !== false : sessionUser.default_cs_reply_enabled === true)
          : true;
        if (isCsEnabled) {
          const customOfflineMsg = sessionUser?.default_cs_reply_text || sessionUser?.custom_offline_message || sysConfig.ai_config.offline_fallback_message ||
            'Halo *{nama}*, terima kasih telah menghubungi kami. Tim Customer Service kami akan segera membalas pesan Anda sesegera mungkin.';
          replyText = customOfflineMsg
            .replace(/\{nama\}/gi, senderName)
            .replace(/\{pesan\}/gi, messageText);
        }
      }
    }

    let sendSucceeded = false;
    let sendErrorDetail: string | undefined;

    if (replyText) {
      // Bound read receipt so stalled privacy IQ never blocks auto-reply delivery
      if (!msg.key.fromMe && antiBan.read_receipt_simulation && typeof sock?.readMessages === 'function') {
        try {
          await delay(100 + crypto.randomInt(0, 180));
          await Promise.race([
            Promise.resolve().then(() => sock.readMessages([msg.key])),
            delay(2500)
          ]);
        } catch (readErr) {
          console.warn('[Baileys Read Receipt error]', readErr);
        }
      }

      // Anti-Ban Simulation & Length-Scaled Random Typing Delay (kept responsive so total reply latency stays fast)
      if (antiBan.enabled) {
        const minS = Math.max(1, Math.min(3, antiBan.min_delay_seconds || 1));
        const maxS = Math.max(minS, Math.min(5, antiBan.max_delay_seconds || 3));
        const baseMs = minS * 1000;
        const spanMs = Math.max(300, (maxS - minS) * 1000);
        const lengthFactor = Math.min(1, replyText.length / 180);
        const jitterMs = crypto.randomInt(0, Math.max(200, Math.floor(spanMs * 0.4)));
        const randomDelayMs = Math.min(maxS * 1000, Math.round(baseMs + spanMs * 0.5 * lengthFactor + jitterMs));

        console.log(`[Baileys Anti-Ban] Typing simulation & random delay (${(randomDelayMs / 1000).toFixed(1)}s) for ${senderPhone}...`);

        if (antiBan.typing_simulation && typeof sock?.sendPresenceUpdate === 'function') {
          void Promise.race([Promise.resolve().then(() => sock.sendPresenceUpdate('composing', replyTargetJid)), delay(1200)]).catch(() => {});
        }

        await delay(randomDelayMs);

        if (antiBan.typing_simulation && typeof sock?.sendPresenceUpdate === 'function') {
          void Promise.race([Promise.resolve().then(() => sock.sendPresenceUpdate('paused', replyTargetJid)), delay(800)]).catch(() => {});
        }
      }

      recordBotOutgoing(replyText);
      let sentQrisSuccessfully = false;
      if (sendQrisImage && (qrisImageUrl || qrisPublicUrl)) {
        const localQrisBuf = resolveLocalCatalogImageBuffer(qrisImageUrl || qrisPublicUrl);
        const imageSource: any = localQrisBuf
          ? localQrisBuf
          : (qrisPublicUrl && /^https?:\/\//i.test(qrisPublicUrl) ? { url: qrisPublicUrl } : null);
        if (imageSource) {
          try {
            await sendSocketMessageWithAckGuard(
              sock,
              replyTargetJid,
              {
                image: imageSource,
                caption: replyText
              },
              { timeoutMs: 30000, fallbackJid: fallbackPnJid, sessionData }
            );
            sentQrisSuccessfully = true;
            sendSucceeded = true;
            console.log(`[Baileys System QRIS Sent] To ${senderPhone} (${qrisImageUrl})`);
          } catch (qrisErr) {
            console.warn('[Baileys QRIS Send Fallback to Text]', qrisErr);
          }
        }
      }

      if (!sentQrisSuccessfully) {
        try {
          await sendSocketMessageWithAckGuard(
            sock,
            replyTargetJid,
            { text: replyText },
            { timeoutMs: 22000, fallbackJid: fallbackPnJid, sessionData }
          );
          sendSucceeded = true;
          console.log(`[Baileys Auto-Reply Sent ${isAi ? '(AI)' : ''}] To ${senderPhone}: "${replyText}"`);
        } catch (replySendErr: any) {
          const replyErrText = String(replySendErr?.message || 'Gagal mengirim balasan otomatis ke WhatsApp');
          sendErrorDetail = replyErrText;
          recordAiAuditEvent({
            level: 'ERROR',
            stage: 'reply_send',
            session_id: sessionId,
            user_id: resolvedOwnerId,
            customer_code: currentOrderFlow?.context.customerCode,
            senderPhone,
            error_code: 'REPLY_SEND_FAILED',
            reason: replyErrText
          });
          console.error(`[Baileys Auto-Reply Send Error] To ${senderPhone}:`, sendErrorDetail);
        }
      }

      if (sendSucceeded) {
        recordCustomerTurn(scopeId, senderPhone, 'assistant', replyText);

        if (sessionUser) {
          const msgDeduct = deductUserDailyQuota(sessionUser.id);
          if (isAi) {
            const aiDeduct = deductUserAiQuota(sessionUser.id);
            console.log(`[Baileys Quota Deducted] AI User ${sessionUser.username}: Daily AI=${aiDeduct.remainingDaily}/${aiDeduct.dailyLimit}, Monthly AI=${aiDeduct.remainingMonthly}/${aiDeduct.monthlyLimit}`);
          } else {
            console.log(`[Baileys Quota Deducted] Msg User ${sessionUser.username}: Daily Msg=${msgDeduct.remaining}/${msgDeduct.dailyLimit}`);
          }
        }
      }
    }

    if (orderPaidVerified && currentOrderFlow) {
      const paidSnapshot = completeAndConsumeVerifiedPaidOrder(scopeId, senderPhone);
      if (paidSnapshot) {
        const ownerTargetPhone =
          resolveOrderNotificationRecipientPhone(resolvedOwnerId) ||
          currentActiveCatalog?.orderNotifyPhone ||
          '';
        if (ownerTargetPhone) {
          const ownerNotifyMsg = formatOwnerOrderNotificationMessage({
            snapshot: paidSnapshot,
            shopName: currentActiveCatalog?.shopName,
            customerPhone: senderPhone,
            customerName: senderName,
            customerNote: rawMessageText,
            hasMediaAttachment
          });
          await sendOrQueueViaSuperadminWa({
            recipientPhone: ownerTargetPhone,
            message: ownerNotifyMsg,
            category: 'order_notification',
            ownerUserId: resolvedOwnerId,
            invoiceNumber: paidSnapshot.invoiceNumber
          }).catch(err => console.warn('[Order Owner Notify Error]', err?.message || err));
        } else {
          console.warn(`[Order Owner Notify] Nomor tujuan pemilik usaha belum tersedia untuk user ${resolvedOwnerId} (Invoice ${paidSnapshot.invoiceNumber}).`);
        }
      }
    }

    const combinedErrorDetail = [aiDiagnosticReason, sendErrorDetail].filter(Boolean).join(' | ') || undefined;

    addMessageLog({
      wam_id: msg.key.id || `baileys_in_${Date.now()}`,
      session_id: dbSession?.id || sessionId,
      user_id: sessionUserId,
      sender_phone: senderPhone,
      sender_name: senderName,
      message_body: messageText,
      direction: 'incoming',
      status: replyText ? (sendSucceeded ? 'Sukses' : 'Gagal') : (aiDiagnosticReason ? 'Gagal' : 'Diterima'),
      reply_body: replyText || undefined,
      error_detail: combinedErrorDetail,
      ai_generated: isAi
    });
  };

  sock.ev.on('messages.upsert', (m: any) => {
    try {
      if (m.type !== 'notify' && m.type !== 'append') return;
      for (const msg of m.messages || []) {
        const chatKeyJid = msg?.key?.remoteJid || msg?.message?.deviceSentMessage?.destinationJid || 'default';
        enqueueIncomingChatTask(`${sessionId}:${chatKeyJid}`, () =>
          handleSingleIncomingMessage(m.type, msg)
        );
      }
    } catch (err) {
      console.error('[Baileys Message Listener Error]', err);
    }
  });
}

function closeSocketSafelyWithoutLogout(sock: any, sessionData?: SessionState | null, sessionId?: string) {
  if (sock) {
    try {
      sock.ev?.removeAllListeners?.('connection.update');
      sock.ev?.removeAllListeners?.('creds.update');
      sock.ev?.removeAllListeners?.('messages.upsert');
      sock.ev?.removeAllListeners?.('messages.update');
      sock.end?.(undefined);
      sock.ws?.removeAllListeners?.();
      try {
        sock.ws?.on?.('error', () => {});
      } catch {}
    } catch {
      // Ignore cleanup errors
    }
  }
  sessionData?.detachRawHandlers?.();
  if (sessionId) {
    clearMetaAiSession(sessionId);
  }
}

/**
 * Mencegah dua folder/socket berbeda milik akun & nomor WA yang sama saling menendang (440 connectionReplaced).
 */
function cleanupDuplicateSessionsForOwnerPhone(keepSessionId: string, ownerUserId: string, cleanPhone: string) {
  if (!keepSessionId || !cleanPhone || cleanPhone.length < 8) return;

  for (const [sid, mem] of Array.from(activeSessions.entries())) {
    if (sid === keepSessionId) continue;
    const memPhone = normalizePhoneNumber(mem.phoneNumber || getCredsPhoneOnDisk(sid) || '');
    const sameUser = !mem.userId || !ownerUserId || mem.userId === ownerUserId || isSessionOwnedByUserId(sid, ownerUserId);
    if (sameUser && memPhone === cleanPhone) {
      console.log(`[Baileys Dedup] Menutup socket duplikat "${sid}" untuk +${cleanPhone} (mempertahankan "${keepSessionId}").`);
      clearSessionTimers(sid);
      closeSocketSafelyWithoutLogout(mem.socket, mem, sid);
      activeSessions.delete(sid);
      cleanSessionFolder(sid);
      deleteBaileysAuthFromMysql(sid).catch(() => {});
    }
  }

  if (fs.existsSync(AUTH_DIR)) {
    try {
      for (const folder of fs.readdirSync(AUTH_DIR)) {
        if (folder === keepSessionId) continue;
        const folderPhone = getCredsPhoneOnDisk(folder);
        if (folderPhone !== cleanPhone) continue;
        const dbMeta = getSessionById(folder);
        const sameOwner =
          (dbMeta?.user_id && dbMeta.user_id === ownerUserId) ||
          isSessionOwnedByUserId(folder, ownerUserId);
        if (sameOwner) {
          console.log(`[Baileys Dedup] Menghapus folder auth duplikat "${folder}" untuk +${cleanPhone}.`);
          clearSessionTimers(folder);
          cleanSessionFolder(folder);
          deleteBaileysAuthFromMysql(folder).catch(() => {});
        }
      }
    } catch {
      // Ignore readdir errors
    }
  }
}

function hasOtherConnectedSocketForPhone(excludeSessionId: string, cleanPhone: string, ownerUserId?: string): boolean {
  if (!cleanPhone || cleanPhone.length < 8) return false;
  for (const [sid, mem] of activeSessions.entries()) {
    if (sid === excludeSessionId) continue;
    if (mem.status !== 'connected' || !isSocketTrulyOpen(mem.socket)) continue;
    const memPhone = normalizePhoneNumber(mem.phoneNumber || '');
    if (memPhone !== cleanPhone) continue;
    if (!ownerUserId || !mem.userId || mem.userId === ownerUserId || isSessionOwnedByUserId(sid, ownerUserId)) {
      return true;
    }
  }
  return false;
}

// Start or get active Baileys socket for QR Code or persistent session
export async function getOrStartBaileysSession(
  rawSessionId: string = 'session_primary_default',
  phoneNumber?: string,
  userId?: string,
  options?: { forceReconnect?: boolean }
): Promise<SessionState> {
  const sessionId = sanitizeSessionId(rawSessionId);
  const existing = activeSessions.get(sessionId);
  if (existing && existing.status === 'connected' && isSocketTrulyOpen(existing.socket)) {
    if (userId && !existing.userId) existing.userId = userId;
    existing.retryCount = 0;
    return existing;
  }

  // If currently connecting/reconnecting or waiting on backoff timer, do NOT kill the in-flight handshake or timer
  if (
    !options?.forceReconnect &&
    existing &&
    existing.status === 'connecting' &&
    (reconnectTimers.has(sessionId) ||
      sessionStartLocks.has(sessionId) ||
      (existing.socket &&
        (isSocketTrulyOpen(existing.socket) || isSocketConnecting(existing.socket)) &&
        Date.now() - existing.lastUpdated < 60000))
  ) {
    if (userId && !existing.userId) existing.userId = userId;
    return existing;
  }

  // Prevent concurrent duplicate socket creation on the same sessionId
  const inFlight = sessionStartLocks.get(sessionId);
  if (inFlight) {
    return inFlight;
  }

  const initPromise = (async (): Promise<SessionState> => {
    try {
      clearSessionTimers(sessionId);

      const current = activeSessions.get(sessionId);
      const preservedUserId = userId || current?.userId;
      const preservedPhone = phoneNumber || current?.phoneNumber || null;
      const prevRetries = options?.forceReconnect ? 0 : (current?.retryCount || 0);
      if (current && current.socket) {
        closeSocketSafelyWithoutLogout(current.socket, current, sessionId);
        activeSessions.delete(sessionId);
      }

      const sessionFolder = safeSessionFolderPath(sessionId);
      if (!sessionFolder) {
        throw new Error('Folder sesi WhatsApp tidak valid.');
      }
      if (!fs.existsSync(sessionFolder)) {
        fs.mkdirSync(sessionFolder, { recursive: true, mode: 0o700 });
      }

      // Restore credentials from Online MySQL if container restarted and local disk is empty
      if (!hasRegisteredCredsOnDisk(sessionId)) {
        await hydrateSessionAuthFolderFromMysql(sessionId);
      } else {
        scheduleAuthFolderBackup(sessionId);
      }

      const { state, saveCreds } = await useMultiFileAuthState(sessionFolder);
      const cachedAuthState = buildCachedAuthState(sessionId, state);
      const cacheStores = getSessionCacheStores(sessionId);
      const version = await resolveBaileysVersion();

      const sock = makeWASocket(
        buildBaileysSocketConfig(version, BAILEYS_SILENT_LOGGER, cachedAuthState, cacheStores)
      );
      try {
        sock.ws?.on?.('error', () => {});
      } catch {}

      const sessionData: SessionState = {
        sessionId,
        userId: preservedUserId,
        socket: sock,
        qrCodeUrl: null,
        pairingCode: null,
        status: 'connecting',
        phoneNumber: preservedPhone,
        lastUpdated: Date.now(),
        handshakeStartedAt: current?.handshakeStartedAt || Date.now(),
        retryCount: prevRetries
      };

      activeSessions.set(sessionId, sessionData);

      // Safe sequential credential saving queue + automatic MySQL backup
      let credsSaveQueue: Promise<void> = Promise.resolve();
      sock.ev.on('creds.update', () => {
        credsSaveQueue = credsSaveQueue.then(async () => {
          try {
            await saveCreds();
            scheduleAuthFolderBackup(sessionId);
          } catch (saveErr) {
            console.warn('[Baileys] Error saving creds:', saveErr);
          }
        });
      });

      sock.ev.on('connection.update', async (update: any) => {
        const { connection, lastDisconnect, qr } = update;

        if (qr) {
          try {
            const qrUrl = await QRCode.toDataURL(qr, { margin: 2, width: 300 });
            sessionData.qrCodeUrl = qrUrl;
            sessionData.lastUpdated = Date.now();
            activeSessions.set(sessionId, sessionData);
          } catch (e) {
            console.error('[Baileys] Error generating QR data URL:', e);
          }
        }

        if (connection === 'open') {
          const rawSockUser = sock.user?.id ? sock.user.id.split('@')[0].split(':')[0] : '';
          const connectedUser = normalizePhoneNumber(rawSockUser || phoneNumber || sessionData.phoneNumber || '');
          if (!connectedUser || connectedUser.length < 8) {
            console.warn(`[Baileys] Connected session ${sessionId} missing valid phone identity; purging.`);
            await purgeBaileysSessionCompletely(sessionId);
            return;
          }

          const db = initDbFile();
          const owner = resolveActiveVerifiedOwner(sessionId, sessionData.userId, connectedUser);
          if (!isOwnerActiveAndRegistered(owner)) {
            console.warn(`[Baileys Security] Connected session ${sessionId} (${connectedUser}) has no active registered user in app. Purging immediately.`);
            await purgeBaileysSessionCompletely(sessionId, connectedUser);
            return;
          }

          console.log(`[Baileys] WhatsApp Connected successfully for session: ${sessionId} (Owner: ${owner!.username})`);
          try {
            await credsSaveQueue;
            await saveCreds();
          } catch {
            // Ignore immediate flush warning; creds.update queue persists async
          }
          sessionData.status = 'connected';
          sessionData.phoneNumber = connectedUser;
          sessionData.qrCodeUrl = null;
          sessionData.pairingCode = null;
          sessionData.lastUpdated = Date.now();
          sessionData.handshakeStartedAt = Date.now();
          sessionData.retryCount = 0;
          sessionData.disconnectedSince = undefined;
          sessionData.userId = owner!.id;
          sessionData.is_primary = Boolean(getSessionById(sessionId)?.is_primary);
          clearSessionExpiryNotificationCooldown(sessionId, owner!.id, connectedUser);
          sessionDisconnectDiagnostics.delete(sessionId);
          cleanupDuplicateSessionsForOwnerPhone(sessionId, owner!.id, connectedUser);
          activeSessions.set(sessionId, sessionData);
          scheduleAuthFolderBackup(sessionId);

          const isPairingMethod = Boolean(phoneNumber) || sessionId.includes('_pair_');
          const existingDb =
            getSessionById(sessionId) ||
            db.sessions.find(
              s =>
                s.user_id === owner!.id &&
                s.phone_number &&
                normalizePhoneNumber(s.phone_number) === connectedUser
            );
          const expiryDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
          const openNowIso = new Date().toISOString();
          if (existingDb) {
            updateSession(existingDb.id, {
              id: sessionId,
              status: 'connected',
              phone_number: connectedUser,
              user_id: owner!.id,
              connected_at: existingDb.connected_at || openNowIso,
              last_activity_at: existingDb.last_activity_at || existingDb.connected_at || openNowIso,
              expires_at: existingDb.expires_at || expiryDate
            });
          } else {
              addSession({
                id: sessionId,
                session_name: isPairingMethod ? `WA Pair - ${connectedUser}` : `WA - ${connectedUser}`,
                phone_number: connectedUser,
                auth_method: isPairingMethod ? 'pairing_code' : 'qr_code',
                status: 'connected',
                user_id: owner!.id,
                is_primary: true,
                connected_at: openNowIso,
                last_activity_at: openNowIso,
                expires_at: expiryDate
              });
            }

          if (owner!.role === 'admin') {
            setTimeout(() => {
              drainSuperadminWaQueue('admin_session_open').catch(() => {});
              processPendingSessionExpiryAlerts('admin_session_open').catch(() => {});
            }, 2500);
          }
        } else if (connection === 'close') {
          const statusCode = (lastDisconnect?.error as any)?.output?.statusCode;
          const disconnectErrMsg = (lastDisconnect?.error as any)?.message ? String((lastDisconnect?.error as any).message) : '';
          recordDisconnectDiagnostic(sessionId, statusCode, disconnectErrMsg);
          const isPermanentLogout = isPermanentLogoutCode(statusCode);
          const isRestartRequired = isRestartRequiredCode(statusCode);
          const hasInMemRegistered = Boolean(sock.authState?.creds?.registered || sock.user?.id);
          if (hasInMemRegistered || isRestartRequired) {
            try {
              await credsSaveQueue;
              await saveCreds();
            } catch {}
          }
          const existingMeta = getSessionById(sessionId);
          const isRegistered =
            hasRegisteredCredsOnDisk(sessionId) ||
            hasInMemRegistered ||
            Boolean(existingMeta?.connected_at);

          // Ignore close events from a superseded socket if a newer socket is already in activeSessions
          const latestSession = activeSessions.get(sessionId);
          if (latestSession && latestSession.socket && latestSession.socket !== sock) {
            return;
          }

          if (isRestartRequired) {
            console.log(
              `[Baileys] Handshake restart required (status ${statusCode ?? 515}, registered: ${isRegistered}) untuk ${sessionId}; menyambung ulang soket...`
            );
          } else {
            console.log(
              `[Baileys] Connection closed for ${sessionId}. Status: ${statusCode}. Registered: ${isRegistered}. PermanentLogout: ${isPermanentLogout}${disconnectErrMsg ? `. Reason: ${disconnectErrMsg}` : ''}`
            );
          }

          try {
            sessionData.detachRawHandlers?.();
            sock.ev?.removeAllListeners?.('connection.update');
            sock.ev?.removeAllListeners?.('creds.update');
            sock.ev?.removeAllListeners?.('messages.upsert');
            sock.ev?.removeAllListeners?.('messages.update');
            sock.ws?.removeAllListeners?.();
            try {
              sock.ws?.on?.('error', () => {});
            } catch {}
          } catch {
            // Ignore listener cleanup errors on closed socket
          }

          sessionData.qrCodeUrl = null;
          sessionData.pairingCode = null;
          sessionData.socket = null;

          if (isPermanentLogout) {
            console.warn(`[Baileys Auto-Purge] Sesi ${sessionId} logout permanen (status ${statusCode}). Menghapus kredensial & data sesi...`);
            const wasPreviouslyLinked = isRegistered || Boolean(sessionData.phoneNumber) || existingMeta?.status === 'connected';
            if (wasPreviouslyLinked) {
              await notifyUserSessionExpired({
                sessionId,
                sessionName: existingMeta?.session_name,
                expiredPhone: sessionData.phoneNumber || existingMeta?.phone_number,
                userId: sessionData.userId || existingMeta?.user_id,
                reason: statusCode === DisconnectReason.loggedOut || statusCode === 401
                  ? 'keluar / terputus dari Perangkat Tertaut di HP'
                  : `terputus permanen (kode ${statusCode})`
              }).catch(() => {});
            }
            await purgeBaileysSessionCompletely(sessionId, sessionData.phoneNumber || undefined);
            return;
          }

          if (!isRegistered && !isRestartRequired) {
            // Unregistered QR/pairing handshake failed or timed out without linking: clean up without touching unrelated sessions
            console.log(`[Baileys Auto-Purge] Sesi ${sessionId} belum terhubung/timeout (${statusCode}). Menghapus folder & cache sementara...`);
            await purgeBaileysSessionCompletely(sessionId, sessionData.phoneNumber || undefined);
            return;
          }

          const owner = resolveActiveVerifiedOwner(sessionId, sessionData.userId, sessionData.phoneNumber || getCredsPhoneOnDisk(sessionId));
          if (!isOwnerActiveAndRegistered(owner)) {
            console.warn(`[Baileys Auto-Purge] Pemilik sesi ${sessionId} tidak aktif/terdaftar lagi. Menghapus sesi...`);
            await purgeBaileysSessionCompletely(sessionId, sessionData.phoneNumber || undefined);
            return;
          }

          const cleanSockPhone = normalizePhoneNumber(sessionData.phoneNumber || getCredsPhoneOnDisk(sessionId) || '');
          if (
            statusCode === DisconnectReason.connectionReplaced &&
            cleanSockPhone &&
            hasOtherConnectedSocketForPhone(sessionId, cleanSockPhone, owner!.id)
          ) {
            console.log(`[Baileys Dedup] Socket ${sessionId} digantikan oleh sesi aktif lain untuk +${cleanSockPhone}; menghentikan duplikat tanpa memutus sesi utama.`);
            clearSessionTimers(sessionId);
            clearMetaAiSession(sessionId);
            activeSessions.delete(sessionId);
            return;
          }

          if (!isRestartRequired) {
            sessionData.retryCount = (sessionData.retryCount || 0) + 1;
          }

          // Only abort/purge unregistered handshakes if they repeatedly fail before ever linking
          if (!isRegistered && sessionData.retryCount > 5) {
            console.warn(`[Baileys Auto-Purge] Handshake baru ${sessionId} gagal berulang (${sessionData.retryCount}x) tanpa tertaut. Menghapus sesi sementara...`);
            await purgeBaileysSessionCompletely(sessionId, sessionData.phoneNumber || undefined);
            return;
          }

          sessionData.status = 'connecting';
          sessionData.lastUpdated = Date.now();
          activeSessions.set(sessionId, sessionData);
          const reconnectDelay = computePersistentReconnectDelay(sessionData.retryCount, statusCode);
          if (isRestartRequired) {
            console.log(
              `[Baileys Persistent Reconnect] Melanjutkan handshake sesi ${sessionId} dalam ${Math.round(reconnectDelay)}ms...`
            );
          } else {
            console.log(
              `[Baileys Persistent Reconnect] Menghubungkan ulang sesi ${sessionId} dalam ${Math.round(reconnectDelay)}ms (percobaan ke-${sessionData.retryCount})...`
            );
          }
          clearSessionTimers(sessionId);
          const rTimer = setTimeout(async () => {
            reconnectTimers.delete(sessionId);
            try {
              await credsSaveQueue;
            } catch {}
            if (!resolveActiveVerifiedOwner(sessionId, sessionData.userId, sessionData.phoneNumber || getCredsPhoneOnDisk(sessionId))) {
              await purgeBaileysSessionCompletely(sessionId);
              return;
            }
            getOrStartBaileysSession(
              sessionId,
              phoneNumber || sessionData.phoneNumber || undefined,
              sessionData.userId,
              { forceReconnect: true }
            ).catch(() => {});
          }, reconnectDelay);
          reconnectTimers.set(sessionId, rTimer);
        }
      });

      // Attach messages upsert listener
      attachSocketMessageListener(sock, sessionId, sessionData);

      return sessionData;
    } finally {
      sessionStartLocks.delete(sessionId);
    }
  })();

  sessionStartLocks.set(sessionId, initPromise);
  return initPromise;
}

// Request real WhatsApp pairing code via Baileys socket
export async function requestBaileysPairingCode(
  rawSessionId: string,
  phoneNumber: string,
  userId?: string
): Promise<string> {
  const sessionId = sanitizeSessionId(rawSessionId);
  const cleanPhone = normalizePhoneNumber(phoneNumber);
  if (!cleanPhone || cleanPhone.length < 9) {
    throw new Error('Nomor telepon tidak valid. Gunakan format lengkap (contoh: 0812... atau 62812...).');
  }

  clearSessionTimers(sessionId);

  const pendingStartLock = sessionStartLocks.get(sessionId);
  if (pendingStartLock) {
    await Promise.race([pendingStartLock.catch(() => {}), delay(3000)]);
  }

  // Safely stop existing sockets on this session ID without deleting DB records yet
  const existing = activeSessions.get(sessionId);
  if (existing && existing.socket) {
    closeSocketSafelyWithoutLogout(existing.socket, existing, sessionId);
    activeSessions.delete(sessionId);
  }

  const sessionFolder = safeSessionFolderPath(sessionId);
  if (!sessionFolder) {
    throw new Error('ID sesi WhatsApp tidak valid.');
  }
  if (fs.existsSync(sessionFolder)) {
    try {
      fs.rmSync(sessionFolder, { recursive: true, force: true });
    } catch (e) {
      console.warn('[Baileys] Warning cleaning session folder for new pairing:', e);
    }
  }
  fs.mkdirSync(sessionFolder, { recursive: true, mode: 0o700 });

  const { state, saveCreds } = await useMultiFileAuthState(sessionFolder);
  const cachedAuthState = buildCachedAuthState(sessionId, state);
  const cacheStores = getSessionCacheStores(sessionId);
  const version = await resolveBaileysVersion();

  const sock = makeWASocket(
    buildBaileysSocketConfig(version, BAILEYS_SILENT_LOGGER, cachedAuthState, cacheStores)
  );
  try {
    sock.ws?.on?.('error', () => {});
  } catch {}

  const sessionData: SessionState = {
    sessionId,
    userId,
    socket: sock,
    qrCodeUrl: null,
    pairingCode: null,
    status: 'connecting',
    phoneNumber: cleanPhone,
    lastUpdated: Date.now(),
    handshakeStartedAt: Date.now(),
    retryCount: 0
  };

  activeSessions.set(sessionId, sessionData);

  // Safe sequential credential saving queue for pairing session
  let pairCredsSaveQueue: Promise<void> = Promise.resolve();
  sock.ev.on('creds.update', () => {
    pairCredsSaveQueue = pairCredsSaveQueue.then(async () => {
      try {
        await saveCreds();
        scheduleAuthFolderBackup(sessionId);
      } catch (saveErr) {
        console.warn('[Baileys Pairing] Error saving creds:', saveErr);
      }
    });
  });

  sock.ev.on('connection.update', async (update: any) => {
    const { connection, lastDisconnect } = update;

    if (connection === 'open') {
      const rawSockUser = sock.user?.id ? sock.user.id.split('@')[0].split(':')[0] : '';
      const connectedUser = normalizePhoneNumber(rawSockUser || cleanPhone);
      const owner = resolveActiveVerifiedOwner(sessionId, sessionData.userId || userId, connectedUser);
      if (!isOwnerActiveAndRegistered(owner)) {
        console.warn(`[Baileys Pairing Security] Connected session ${sessionId} has no active registered owner. Purging.`);
        await purgeBaileysSessionCompletely(sessionId, connectedUser);
        return;
      }

      console.log(`[Baileys Pairing] Connected & Linked successfully! User: ${sock.user?.id}`);
      try {
        await pairCredsSaveQueue;
        await saveCreds();
      } catch {
        // Ignore flush warning; creds.update queue persists async
      }
      sessionData.status = 'connected';
      sessionData.phoneNumber = connectedUser;
      sessionData.pairingCode = null;
      sessionData.lastUpdated = Date.now();
      sessionData.handshakeStartedAt = Date.now();
      sessionData.retryCount = 0;
      sessionData.disconnectedSince = undefined;
      sessionData.userId = owner!.id;
      clearSessionExpiryNotificationCooldown(sessionId, owner!.id, connectedUser);
      sessionDisconnectDiagnostics.delete(sessionId);
      cleanupDuplicateSessionsForOwnerPhone(sessionId, owner!.id, connectedUser);
      activeSessions.set(sessionId, sessionData);
      scheduleAuthFolderBackup(sessionId);

      const db = initDbFile();
      const existingDb =
        getSessionById(sessionId) ||
        db.sessions.find(
          s =>
            s.user_id === owner!.id &&
            s.phone_number &&
            normalizePhoneNumber(s.phone_number) === connectedUser
        );
      const expiryDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
      const pairOpenIso = new Date().toISOString();
      if (existingDb) {
        updateSession(existingDb.id, {
          id: sessionId,
          status: 'connected',
          phone_number: connectedUser,
          user_id: owner!.id,
          connected_at: existingDb.connected_at || pairOpenIso,
          last_activity_at: existingDb.last_activity_at || existingDb.connected_at || pairOpenIso,
          expires_at: existingDb.expires_at || expiryDate
        });
      } else {
          addSession({
            id: sessionId,
            session_name: `WA Pair - ${connectedUser}`,
            phone_number: connectedUser,
            auth_method: 'pairing_code',
            status: 'connected',
            user_id: owner!.id,
            is_primary: true,
            connected_at: pairOpenIso,
            last_activity_at: pairOpenIso,
            expires_at: expiryDate
          });
        }

        if (owner!.role === 'admin') {
          setTimeout(() => {
            drainSuperadminWaQueue('admin_pairing_open').catch(() => {});
            processPendingSessionExpiryAlerts('admin_pairing_open').catch(() => {});
          }, 2500);
        }
      } else if (connection === 'close') {
      const statusCode = (lastDisconnect?.error as any)?.output?.statusCode;
      const disconnectErrMsg = (lastDisconnect?.error as any)?.message ? String((lastDisconnect?.error as any).message) : '';
      recordDisconnectDiagnostic(sessionId, statusCode, disconnectErrMsg);
      const isPermanentLogout = isPermanentLogoutCode(statusCode);
      const isPairRestartRequired = isRestartRequiredCode(statusCode);
      const hasInMemRegistered = Boolean(sock.authState?.creds?.registered || sock.user?.id);
      if (hasInMemRegistered || isPairRestartRequired) {
        try {
          await pairCredsSaveQueue;
          await saveCreds();
        } catch {}
      }
      const existingMeta = getSessionById(sessionId);
      const isRegistered =
        hasRegisteredCredsOnDisk(sessionId) ||
        hasInMemRegistered ||
        Boolean(existingMeta?.connected_at);

      if (isPairRestartRequired) {
        console.log(
          `[Baileys Pairing] Handshake restart required (code ${statusCode ?? 515}, registered: ${isRegistered}) untuk ${sessionId}; menyambung ulang sesi...`
        );
      } else {
        console.log(
          `[Baileys Pairing] Connection closed ${sessionId}, code: ${statusCode}, registered: ${isRegistered}${disconnectErrMsg ? `, reason: ${disconnectErrMsg}` : ''}`
        );
      }

      const latestSession = activeSessions.get(sessionId);
      if (latestSession && latestSession.socket && latestSession.socket !== sock) {
        return;
      }

      try {
        sessionData.detachRawHandlers?.();
        sock.ev?.removeAllListeners?.('connection.update');
        sock.ev?.removeAllListeners?.('creds.update');
        sock.ev?.removeAllListeners?.('messages.upsert');
        sock.ev?.removeAllListeners?.('messages.update');
        sock.ws?.removeAllListeners?.();
        try {
          sock.ws?.on?.('error', () => {});
        } catch {}
      } catch {
        // Ignore listener cleanup errors on closed pairing socket
      }

      sessionData.socket = null;

      if (isPermanentLogout || (!isRegistered && !isPairRestartRequired)) {
        console.warn(`[Baileys Pairing Auto-Purge] Sesi pairing ${sessionId} terputus/batal (${statusCode}). Menghapus sesi sementara...`);
        if (isPermanentLogout && (isRegistered || existingMeta?.status === 'connected')) {
          await notifyUserSessionExpired({
            sessionId,
            sessionName: existingMeta?.session_name,
            expiredPhone: sessionData.phoneNumber || cleanPhone || existingMeta?.phone_number,
            userId: sessionData.userId || userId || existingMeta?.user_id,
            reason: statusCode === DisconnectReason.loggedOut || statusCode === 401
              ? 'keluar / terputus dari Perangkat Tertaut di HP'
              : `terputus permanen (kode ${statusCode})`
          }).catch(() => {});
        }
        await purgeBaileysSessionCompletely(sessionId, cleanPhone);
        return;
      }

      const pairOwner = resolveActiveVerifiedOwner(sessionId, sessionData.userId || userId, sessionData.phoneNumber || cleanPhone);
      if (!isOwnerActiveAndRegistered(pairOwner)) {
        console.warn(`[Baileys Pairing Auto-Purge] Pemilik sesi pairing ${sessionId} tidak aktif/terdaftar. Menghapus sesi...`);
        await purgeBaileysSessionCompletely(sessionId, cleanPhone);
        return;
      }

      if (
        statusCode === DisconnectReason.connectionReplaced &&
        cleanPhone &&
        hasOtherConnectedSocketForPhone(sessionId, cleanPhone, pairOwner!.id)
      ) {
        clearSessionTimers(sessionId);
        clearMetaAiSession(sessionId);
        activeSessions.delete(sessionId);
        return;
      }

      if (!isPairRestartRequired) {
        sessionData.retryCount = (sessionData.retryCount || 0) + 1;
      }
      if (!isRegistered && sessionData.retryCount > 5) {
        await purgeBaileysSessionCompletely(sessionId, cleanPhone);
        return;
      }

      sessionData.status = 'connecting';
      sessionData.lastUpdated = Date.now();
      activeSessions.set(sessionId, sessionData);
      const pairReconnectDelay = computePersistentReconnectDelay(sessionData.retryCount, statusCode);
      if (isPairRestartRequired) {
        console.log(
          `[Baileys Pairing Reconnect] Melanjutkan penautan ${sessionId} setelah restart 515 dalam ${Math.round(pairReconnectDelay)}ms...`
        );
      } else {
        console.log(
          `[Baileys Pairing Persistent Reconnect] Stream closed (${statusCode}). Reconnecting ${sessionId} (attempt ${sessionData.retryCount})...`
        );
      }
      clearSessionTimers(sessionId);
      const rTimer = setTimeout(async () => {
        reconnectTimers.delete(sessionId);
        try {
          await pairCredsSaveQueue;
        } catch {}
        if (!resolveActiveVerifiedOwner(sessionId, sessionData.userId || userId, sessionData.phoneNumber || cleanPhone)) {
          await purgeBaileysSessionCompletely(sessionId, cleanPhone);
          return;
        }
        getOrStartBaileysSession(sessionId, cleanPhone, sessionData.userId || userId, { forceReconnect: true }).catch(() => {});
      }, pairReconnectDelay);
      reconnectTimers.set(sessionId, rTimer);
    }
  });

  // Attach messages upsert listener to pairing socket as well
  attachSocketMessageListener(sock, sessionId, sessionData);

  // Wait for WebSocket connection to establish before requesting code
  let tries = 0;
  while (tries < 18 && !sock.ws?.isOpen && !sock.ws?.isClosed) {
    await delay(300);
    tries++;
  }
  await delay(800);

  if (!sock.authState.creds.registered) {
    try {
      const rawCode = await sock.requestPairingCode(cleanPhone);
      const formattedCode = rawCode?.match(/.{1,4}/g)?.join('-') || rawCode;
      sessionData.pairingCode = formattedCode;
      sessionData.lastUpdated = Date.now();
      activeSessions.set(sessionId, sessionData);

      // Jangan langsung menyimpan ke db.sessions sebelum perangkat benar-benar berhasil tertaut (`connection === 'open'`)
      return formattedCode;
    } catch (err: any) {
      console.error('[Baileys] Request pairing code error:', err);
      const alreadyLinkedOrRestarting =
        Boolean(sock.authState?.creds?.registered) ||
        hasRegisteredCredsOnDisk(sessionId) ||
        reconnectTimers.has(sessionId);
      if (!alreadyLinkedOrRestarting) {
        await purgeBaileysSessionCompletely(sessionId, cleanPhone);
      }
      throw new Error(err?.message || 'Gagal meminta Kode Pairing dari WhatsApp.');
    }
  } else {
    throw new Error('Sesi ini sudah terdaftar dan terhubung.');
  }
}

export function getLiveSessionRuntimeStatus(dbSess: {
  id: string;
  user_id?: string;
  phone_number?: string;
}): {
  runtime_status: 'connected' | 'connecting' | 'disconnected';
  has_registered_creds: boolean;
} {
  let mem = activeSessions.get(dbSess.id);
  if (!mem) {
    const cleanPhone = normalizePhoneNumber(dbSess.phone_number || '');
    for (const s of activeSessions.values()) {
      if (s.userId && dbSess.user_id && s.userId !== dbSess.user_id) continue;
      if (
        s.sessionId === dbSess.id ||
        (cleanPhone.length >= 8 && s.phoneNumber && normalizePhoneNumber(s.phoneNumber) === cleanPhone)
      ) {
        mem = s;
        break;
      }
    }
  }

  let hasCreds = hasRegisteredCredsOnDisk(dbSess.id);
  if (!hasCreds && mem && mem.sessionId !== dbSess.id) {
    hasCreds = hasRegisteredCredsOnDisk(mem.sessionId);
  }

  if (mem) {
    if (mem.status === 'connected' && isSocketTrulyOpen(mem.socket)) {
      return { runtime_status: 'connected', has_registered_creds: true };
    }
    if (mem.status === 'connecting') {
      return { runtime_status: 'connecting', has_registered_creds: hasCreds };
    }
  }

  if (reconnectTimers.has(dbSess.id) || sessionStartLocks.has(dbSess.id)) {
    return { runtime_status: 'connecting', has_registered_creds: hasCreds };
  }

  return { runtime_status: 'disconnected', has_registered_creds: hasCreds };
}

export async function reconnectBaileysSessionForUser(
  rawSessionId: string,
  userId?: string
): Promise<{
  connected: boolean;
  runtime_status: 'connected' | 'connecting' | 'disconnected';
  needs_rescan: boolean;
  session_id: string;
  phone_number?: string;
  disconnect_code?: number;
  disconnect_reason?: string;
}> {
  const sessionId = sanitizeSessionId(rawSessionId);
  const dbSess = getSessionById(sessionId);
  const effectiveId = dbSess?.id || sessionId;
  const targetUserId = userId || dbSess?.user_id;

  const liveNow = findLiveSocketEntry(targetUserId, effectiveId);
  if (liveNow) {
    return {
      connected: true,
      runtime_status: 'connected',
      needs_rescan: false,
      session_id: liveNow.sessionId,
      phone_number: liveNow.phoneNumber || dbSess?.phone_number
    };
  }

  let hasCreds = hasRegisteredCredsOnDisk(effectiveId);
  if (!hasCreds) {
    hasCreds = await hydrateSessionAuthFolderFromMysql(effectiveId).catch(() => false);
  }
  if (!hasCreds && effectiveId !== sessionId) {
    hasCreds =
      hasRegisteredCredsOnDisk(sessionId) ||
      (await hydrateSessionAuthFolderFromMysql(sessionId).catch(() => false));
  }

  if (!hasCreds) {
    const diag = sessionDisconnectDiagnostics.get(effectiveId) || sessionDisconnectDiagnostics.get(sessionId);
    return {
      connected: false,
      runtime_status: 'disconnected',
      needs_rescan: true,
      session_id: effectiveId,
      phone_number: dbSess?.phone_number,
      disconnect_code: diag?.code,
      disconnect_reason: diag?.reason
    };
  }

  const startedState = await getOrStartBaileysSession(
    effectiveId,
    dbSess?.phone_number,
    targetUserId,
    { forceReconnect: true }
  );

  let tries = 0;
  while (tries < 18 && startedState.status === 'connecting') {
    await delay(400);
    const ready = findLiveSocketEntry(targetUserId, effectiveId);
    if (ready) {
      return {
        connected: true,
        runtime_status: 'connected',
        needs_rescan: false,
        session_id: ready.sessionId,
        phone_number: ready.phoneNumber || dbSess?.phone_number
      };
    }
    tries++;
  }

  const afterWait = findLiveSocketEntry(targetUserId, effectiveId);
  if (afterWait) {
    return {
      connected: true,
      runtime_status: 'connected',
      needs_rescan: false,
      session_id: afterWait.sessionId,
      phone_number: afterWait.phoneNumber || dbSess?.phone_number
    };
  }

  const mem = activeSessions.get(effectiveId);
  return {
    connected: false,
    runtime_status: mem?.status === 'connecting' ? 'connecting' : 'disconnected',
    needs_rescan: false,
    session_id: effectiveId,
    phone_number: dbSess?.phone_number
  };
}

export function getBaileysSessionStatus(idOrPhone: string) {
  const cleanKey = String(idOrPhone || '').trim();
  if (!cleanKey) return null;
  let session = activeSessions.get(cleanKey);

  if (!session && /^\+?\d{8,16}$/.test(cleanKey)) {
    const cleanPhone = normalizePhoneNumber(cleanKey);
    for (const s of activeSessions.values()) {
      const memPhone = normalizePhoneNumber(s.phoneNumber || '');
      if (cleanPhone && memPhone && memPhone === cleanPhone) {
        session = s;
        break;
      }
    }
  }

  if (session) {
    return {
      sessionId: session.sessionId,
      qrCodeUrl: session.qrCodeUrl,
      pairingCode: session.pairingCode,
      status: session.status,
      phoneNumber: session.phoneNumber,
      lastUpdated: session.lastUpdated
    };
  }

  // Fallback to database record if session connected
  try {
    const dbSess = getSessionById(idOrPhone);
    if (dbSess && dbSess.status !== 'disconnected') {
      return {
        sessionId: dbSess.id,
        qrCodeUrl: null,
        pairingCode: null,
        status: dbSess.status,
        phoneNumber: dbSess.phone_number,
        lastUpdated: Date.now()
      };
    }
  } catch {}

  return null;
}

export async function purgeBaileysSessionCompletely(
  idOrPhone: string,
  explicitPhone?: string,
  options?: { allowRemoteLogout?: boolean }
): Promise<void> {
  if (!idOrPhone) return;

  clearSessionTimers(idOrPhone);

  const sess = getSessionById(idOrPhone);
  const credsPhone = getCredsPhoneOnDisk(idOrPhone);
  const rawPhoneInput = /^\+?\d{8,16}$/.test(idOrPhone.trim()) ? idOrPhone.trim() : '';
  const targetPhone = normalizePhoneNumber(explicitPhone || sess?.phone_number || credsPhone || rawPhoneInput);
  const targetUserId = sess?.user_id;

  // 1. Delete from DB and MySQL Auth Backup immediately
  deleteSession(idOrPhone);
  deleteBaileysAuthFromMysql(idOrPhone).catch(() => {});
  if (sess?.id && sess.id !== idOrPhone) {
    clearSessionTimers(sess.id);
    deleteSession(sess.id);
    deleteBaileysAuthFromMysql(sess.id).catch(() => {});
  }
  if (rawPhoneInput && targetPhone.length >= 8) {
    deleteSession(targetPhone);
  }

  // 2. Terminate matching active sockets & clear timers/dialog state (NEVER match unrelated sessions by userId timestamp digits)
  const keysToRemove: string[] = [];
  for (const [key, sessionData] of activeSessions.entries()) {
    const memPhone = normalizePhoneNumber(sessionData.phoneNumber || '');
    const sameOwner = !targetUserId || !sessionData.userId || sessionData.userId === targetUserId;
    const isExactMatch = key === idOrPhone || Boolean(sess && key === sess.id);
    const isSamePhoneMatch =
      Boolean(targetPhone && targetPhone.length >= 8 && sameOwner && memPhone && memPhone === targetPhone);
    if (isExactMatch || isSamePhoneMatch) {
      clearSessionTimers(key);
      if (sessionData.socket) {
        if (options?.allowRemoteLogout) {
          try {
            await Promise.race([
              sessionData.socket.logout().catch(() => {}),
              new Promise(res => setTimeout(res, 600))
            ]);
          } catch {
            // Ignore remote logout errors
          }
        }
        try {
          sessionData.socket.ev?.removeAllListeners?.('connection.update');
          sessionData.socket.ev?.removeAllListeners?.('creds.update');
          sessionData.socket.ev?.removeAllListeners?.('messages.upsert');
          sessionData.socket.ev?.removeAllListeners?.('messages.update');
          sessionData.socket.end(undefined);
          sessionData.socket.ws?.removeAllListeners?.();
        } catch {
          // Ignore socket close errors
        }
      }
      sessionData.detachRawHandlers?.();
      clearMetaAiSession(key);
      keysToRemove.push(key);
    }
  }

  for (const k of keysToRemove) {
    activeSessions.delete(k);
    lastAuthBackupAt.delete(k);
    lastAuthBackupHashes.delete(k);
    clearSessionCacheStores(k);
    cleanSessionFolder(k);
    deleteBaileysAuthFromMysql(k).catch(() => {});
    for (const stateKey of Array.from(commandState.keys())) {
      if (stateKey.startsWith(`${k}:`)) {
        commandState.delete(stateKey);
      }
    }
  }

  // 3. Clean matching session folders on disk
  cleanSessionFolder(idOrPhone);
  if (sess?.id) cleanSessionFolder(sess.id);
  if (rawPhoneInput && targetPhone.length >= 8) {
    cleanSessionFolder(`session_${targetPhone}`);
    cleanSessionFolder(`session_pair_${targetPhone}`);
  }
}

export async function evictAndPurgeFreeSession(
  sessionId: string,
  reason = 'Slot kapasitas dibutuhkan oleh pengguna paket berbayar'
): Promise<void> {
  if (!sessionId) return;
  console.warn(`[Baileys Slot Eviction] Menggeser & menghapus sesi Free "${sessionId}" (${reason}).`);
  await purgeBaileysSessionCompletely(sessionId, undefined, { allowRemoteLogout: true });
}

export async function stopBaileysSession(idOrPhone: string) {
  if (!idOrPhone) return;
  console.log(`[Baileys] Stopping and purging session: ${idOrPhone}`);
  await purgeBaileysSessionCompletely(idOrPhone, undefined, { allowRemoteLogout: true });
}

export async function parkSocketToSaveRam(_sessionId: string, _markDbDisconnected = false): Promise<boolean> {
  // Socket keep-alive persisten diaktifkan untuk semua user agar tidak terputus otomatis
  return false;
}

export async function stopIdleUserBaileysSockets(_userId: string): Promise<number> {
  // Koneksi WhatsApp tetap terjaga persisten meskipun sakelar Auto-Reply OFF
  return 0;
}

export async function resumeSavedUserBaileysSessions(userId: string): Promise<number> {
  if (!userId) return 0;
  const user = getUserById(userId);
  if (!isOwnerActiveAndRegistered(user)) return 0;

  let started = 0;
  const userSessions = getSessionsByUserId(userId);
  for (const s of userSessions) {
    if (!s.id) continue;
    if (s.expires_at && new Date(s.expires_at).getTime() < Date.now()) continue;
    const mem = activeSessions.get(s.id);
    if (mem && mem.status === 'connected' && isSocketTrulyOpen(mem.socket)) continue;
    let hasCreds = hasRegisteredCredsOnDisk(s.id);
    if (!hasCreds) {
      hasCreds = await hydrateSessionAuthFolderFromMysql(s.id).catch(() => false);
    }
    if (hasCreds) {
      getOrStartBaileysSession(s.id, s.phone_number, userId).catch(() => {});
      started++;
    }
  }
  return started;
}

export async function purgeBaileysSessionsForUser(userId: string): Promise<number> {
  if (!userId) return 0;
  const db = initDbFile();
  const targetUser = getUserById(userId);
  const toPurge = new Set<string>();

  for (const s of db.sessions) {
    if (s.user_id === userId || (targetUser && s.user_id === targetUser.id) || isSessionOwnedByUserId(s.id, userId)) {
      toPurge.add(s.id);
    }
  }
  for (const [sid, mem] of activeSessions.entries()) {
    if (mem.userId === userId || (targetUser && mem.userId === targetUser.id) || isSessionOwnedByUserId(sid, userId)) {
      toPurge.add(sid);
    }
  }
  if (fs.existsSync(AUTH_DIR)) {
    for (const folder of fs.readdirSync(AUTH_DIR)) {
      if (isSessionOwnedByUserId(folder, userId)) toPurge.add(folder);
    }
  }

  for (const sid of toPurge) {
    await purgeBaileysSessionCompletely(sid);
  }
  return toPurge.size;
}

let pruneInFlightPromise: Promise<number> | null = null;
let lastPruneCompletedAt = 0;
let lastMysqlAuthPruneAt = 0;

/**
 * Automatically purges Baileys sessions that are:
 * - Inactive/disconnected (`status === 'disconnected'` with no live socket, or expired `expires_at`)
 * - Stale unscanned QR/pairing handshakes (`> 3 min` without registered creds)
 * - Unregistered/orphan (owner user deleted, inactive, or email unverified, OR orphan auth folder whose phone/session is not registered in app)
 */
export async function pruneInactiveAndUnregisteredBaileysSessions(force = false): Promise<number> {
  if (pruneInFlightPromise) {
    return pruneInFlightPromise;
  }
  const now = Date.now();
  if (!force && now - lastPruneCompletedAt < PRUNE_COOLDOWN_MS) {
    return 0;
  }

  pruneInFlightPromise = (async () => {
    let purgedCount = 0;
    const db = initDbFile();
    const purgedIds = new Set<string>();

    const doPurge = async (sid: string, phone?: string, reason?: string) => {
      if (!sid || purgedIds.has(sid)) return;
      purgedIds.add(sid);
      purgedCount++;
      console.log(`[Baileys Auto-Purge] Menghapus sesi "${sid}" (${reason || 'inactive/unregistered'}).`);
      await purgeBaileysSessionCompletely(sid, phone);
    };

    try {
      // 1. Check all DB Baileys sessions
      for (const s of [...db.sessions]) {
        const mem = activeSessions.get(s.id);
        const hasOpenSocket = Boolean(mem && mem.status === 'connected' && isSocketTrulyOpen(mem.socket));

    const owner = resolveActiveVerifiedOwner(s.id, s.user_id, s.phone_number);
    if (!isOwnerActiveAndRegistered(owner)) {
      await doPurge(s.id, s.phone_number, 'pemilik akun tidak terdaftar atau nonaktif');
      continue;
    }

    if (s.expires_at && new Date(s.expires_at).getTime() < now) {
      if (s.phone_number) {
        await notifyUserSessionExpired({
          sessionId: s.id,
          sessionName: s.session_name,
          expiredPhone: s.phone_number,
          userId: s.user_id,
          reason: 'masa aktif sesi login telah habis (expired)'
        }).catch(() => {});
      }
      await doPurge(s.id, s.phone_number, 'masa aktif sesi berakhir');
      continue;
    }

    // Hapus otomatis sesi Perangkat Tertaut apabila tidak ada aktivitas pesan masuk maupun balasan selama 3 hari (72 jam)
    const lastActivityIso = s.last_activity_at || s.connected_at || s.updated_at || s.created_at;
    const lastActivityMs = lastActivityIso ? Date.parse(lastActivityIso) : NaN;
    const isLinkedSession = s.status === 'connected' || Boolean(s.connected_at) || hasRegisteredCredsOnDisk(s.id);
    if (
      isLinkedSession &&
      Number.isFinite(lastActivityMs) &&
      now - lastActivityMs >= SESSION_INACTIVITY_PURGE_MS
    ) {
      await doPurge(
        s.id,
        s.phone_number,
        'tidak ada pesan masuk atau balasan selama 3 hari berturut-turut'
      );
      continue;
    }

    if (s.status === 'disconnected' && !hasOpenSocket && !hasRegisteredCredsOnDisk(s.id)) {
      const hydrated = isMysqlConfigured()
        ? await hydrateSessionAuthFolderFromMysql(s.id).catch(() => false)
        : false;
      if (!hydrated) {
        if (s.phone_number && s.connected_at) {
          await notifyUserSessionExpired({
            sessionId: s.id,
            sessionName: s.session_name,
            expiredPhone: s.phone_number,
            userId: s.user_id,
            reason: 'sesi WhatsApp terputus dan kredensial login tidak aktif lagi'
          }).catch(() => {});
        }
        await doPurge(s.id, s.phone_number, 'status sesi disconnected tanpa kredensial tersimpan');
        continue;
      }
    }

    const updatedMs = new Date(s.updated_at || s.created_at || 0).getTime();
    if (
      s.status === 'connecting' &&
      !s.connected_at &&
      !hasRegisteredCredsOnDisk(s.id) &&
      (!mem || now - mem.handshakeStartedAt > UNSCANNED_HANDSHAKE_TTL_MS) &&
      now - updatedMs > UNSCANNED_HANDSHAKE_TTL_MS
    ) {
      await doPurge(s.id, s.phone_number, 'handshake QR/pairing kadaluarsa tanpa scan');
      continue;
    }
  }

  // 2. Check all in-memory Baileys sockets
  for (const [sid, mem] of Array.from(activeSessions.entries())) {
    if (purgedIds.has(sid)) continue;
    const summary = readCredsSummary(sid);
    const dbSess = getSessionById(sid);
    const memRegistered = Boolean(mem.socket?.authState?.creds?.registered || mem.socket?.user?.id);
    const owner = resolveActiveVerifiedOwner(sid, mem.userId, mem.phoneNumber || summary.phone);

    if (!isOwnerActiveAndRegistered(owner)) {
      await doPurge(sid, mem.phoneNumber || summary.phone, 'socket memori tidak memiliki pemilik terdaftar aktif');
      continue;
    }

    if (dbSess?.expires_at && new Date(dbSess.expires_at).getTime() < now) {
      await doPurge(sid, mem.phoneNumber || summary.phone, 'masa aktif sesi di memori berakhir');
      continue;
    }

    if (!summary.registered && !memRegistered && !dbSess?.connected_at && now - mem.handshakeStartedAt > UNSCANNED_HANDSHAKE_TTL_MS) {
      await doPurge(sid, mem.phoneNumber || undefined, 'QR/pairing belum tersambung > 3 menit');
      continue;
    }

    if (mem.status === 'disconnected' && !isSocketTrulyOpen(mem.socket)) {
      if (!summary.registered && !memRegistered && !dbSess?.connected_at) {
        await doPurge(sid, mem.phoneNumber || summary.phone, 'socket terputus tanpa kredensial');
        continue;
      }
      // Re-attach persistent socket on next watchdog cycle
      if (mem.disconnectedSince && now - mem.disconnectedSince > 10 * 60 * 1000) {
        clearSessionTimers(sid);
        clearMetaAiSession(sid);
        activeSessions.delete(sid);
      }
    }
  }

  // 3. Check all local disk auth folders
  if (fs.existsSync(AUTH_DIR)) {
    for (const entry of fs.readdirSync(AUTH_DIR)) {
      if (purgedIds.has(entry)) continue;
      const folderPath = safeSessionFolderPath(entry);
      if (!folderPath) continue;
      try {
        const stat = fs.lstatSync(folderPath);
        if (!stat.isDirectory()) continue;

        const mem = activeSessions.get(entry);
        const dbSess = getSessionById(entry);
        const { registered: isRegistered, phone: credsPhone } = readCredsSummary(entry);
        const memRegistered = Boolean(mem?.socket?.authState?.creds?.registered || mem?.socket?.user?.id);

        if (!isRegistered && !memRegistered) {
          const isFreshConnecting = mem && mem.status === 'connecting' && now - mem.handshakeStartedAt <= UNSCANNED_HANDSHAKE_TTL_MS;
          if (!isFreshConnecting && now - stat.mtimeMs > UNSCANNED_HANDSHAKE_TTL_MS) {
            await doPurge(entry, credsPhone, 'folder auth tidak terdaftar & kadaluarsa');
          }
          continue;
        }

        const owner = resolveActiveVerifiedOwner(entry, dbSess?.user_id || mem?.userId, dbSess?.phone_number || credsPhone);
        if (!isOwnerActiveAndRegistered(owner)) {
          await doPurge(entry, credsPhone, 'folder auth milik user yang sudah terhapus/nonaktif');
          continue;
        }

        if (dbSess?.expires_at && new Date(dbSess.expires_at).getTime() < now) {
          await doPurge(entry, credsPhone, 'folder auth sudah melewati tanggal kedaluwarsa');
          continue;
        }

        // Recover DB session entry when disk creds remain valid after build/restart
        if (!dbSess && owner) {
          addSession({
            id: entry,
            session_name: `WA - ${credsPhone || entry}`,
            phone_number: credsPhone || '',
            auth_method: 'qr_code',
            status: 'connected',
            user_id: owner.id,
            is_primary: true
          });
        }
      } catch {
        // Ignore stat race
      }
    }
  }

      // 4. Check MySQL backed up Baileys auth keys (throttled to reduce MySQL queries)
      if (isMysqlConfigured() && (force || now - lastMysqlAuthPruneAt >= MYSQL_AUTH_PRUNE_INTERVAL_MS)) {
        lastMysqlAuthPruneAt = now;
        const mysqlAuthIds = await loadAllBaileysAuthSessionIdsFromMysql().catch(() => []);
        for (const sid of mysqlAuthIds) {
          if (purgedIds.has(sid)) continue;
          const dbSess = getSessionById(sid);
          const owner = resolveActiveVerifiedOwner(sid, dbSess?.user_id, dbSess?.phone_number);
          const isExpired = Boolean(dbSess?.expires_at && new Date(dbSess.expires_at).getTime() < now);
          const hasDiskCreds = hasRegisteredCredsOnDisk(sid);
          if (!isOwnerActiveAndRegistered(owner) || isExpired || (!dbSess && !hasDiskCreds)) {
            await doPurge(sid, dbSess?.phone_number, 'backup auth MySQL tidak memiliki pemilik/sesi aktif atau sudah expired');
          }
        }
      }

      return purgedCount;
    } finally {
      lastPruneCompletedAt = Date.now();
      pruneInFlightPromise = null;
    }
  })();

  return pruneInFlightPromise;
}

// Helper to check if a session folder has valid registered credentials on disk
function hasRegisteredCredsOnDisk(sessionId: string): boolean {
  return readCredsSummary(sessionId).registered;
}

export function getPreferredSystemBaileysSessionId(): string | null {
  const db = initDbFile();
  const isAdminUser = (uid?: string) => {
    if (!uid) return false;
    const u = getUserById(uid);
    return Boolean(u && u.role === 'admin' && u.is_active);
  };

  // 1. Only pick live connected sessions owned by an Admin/Superadmin
  const connectedAdmin = Array.from(activeSessions.values()).filter(
    s => s.status === 'connected' && isSocketTrulyOpen(s.socket) && isAdminUser(s.userId)
  );
  if (connectedAdmin.length > 0) {
    const prim = connectedAdmin.find(s => s.is_primary);
    return prim ? prim.sessionId : connectedAdmin[0].sessionId;
  }

  // 2. Fallback to admin DB sessions that are active/connected
  const adminDb = db.sessions.filter(
    s => s.status === 'connected' && isAdminUser(s.user_id)
  );
  const primDb = adminDb.find(s => s.is_primary);
  return primDb?.id || adminDb[0]?.id || null;
}

// Auto-restore all saved active WhatsApp sessions on server startup
let isRestoringSessions = false;
export async function restoreSavedBaileysSessions() {
  if (isRestoringSessions) return;
  isRestoringSessions = true;
  try {
    const mysqlBackedUpIds = await loadAllBaileysAuthSessionIdsFromMysql().catch(() => []);
    for (const sid of mysqlBackedUpIds) {
      const dbSess = getSessionById(sid);
      const owner = resolveActiveVerifiedOwner(sid, dbSess?.user_id, dbSess?.phone_number);
      if (!isOwnerActiveAndRegistered(owner)) continue;
      if (dbSess?.expires_at && new Date(dbSess.expires_at).getTime() < Date.now()) continue;
      await hydrateSessionAuthFolderFromMysql(sid).catch(() => false);
    }

    // Purge expired or ownerless sessions AFTER hydrating valid backups from MySQL
    await pruneInactiveAndUnregisteredBaileysSessions(true).catch(() => {});

    const dbSessions = getWhatsAppSessions();
    const diskFolders = fs.existsSync(AUTH_DIR) ? fs.readdirSync(AUTH_DIR) : [];

    const sessionIdsToRestore = new Set<string>();

    const canAutoStartOwner = (owner: ReturnType<typeof getUserById>): boolean => {
      return isOwnerActiveAndRegistered(owner);
    };

    for (const sid of mysqlBackedUpIds) {
      const dbSess = getSessionById(sid);
      const owner = resolveActiveVerifiedOwner(sid, dbSess?.user_id, dbSess?.phone_number);
      if (!canAutoStartOwner(owner)) continue;
      if (dbSess?.expires_at && new Date(dbSess.expires_at).getTime() < Date.now()) continue;

      await hydrateSessionAuthFolderFromMysql(sid);
      if (hasRegisteredCredsOnDisk(sid)) {
        sessionIdsToRestore.add(sid);
      }
    }

    dbSessions.forEach(s => {
      if (s.id && hasRegisteredCredsOnDisk(s.id)) {
        const owner = resolveActiveVerifiedOwner(s.id, s.user_id, s.phone_number);
        const notExpired = !s.expires_at || new Date(s.expires_at).getTime() >= Date.now();
        if (canAutoStartOwner(owner) && notExpired) {
          sessionIdsToRestore.add(s.id);
        }
      }
    });

    diskFolders.forEach(folder => {
      const folderPath = safeSessionFolderPath(folder);
      if (!folderPath) return;
      if (fs.lstatSync(folderPath).isDirectory() && hasRegisteredCredsOnDisk(folder)) {
        const dbSess = getSessionById(folder);
        const credsPhone = getCredsPhoneOnDisk(folder);
        const owner = resolveActiveVerifiedOwner(folder, dbSess?.user_id, dbSess?.phone_number || credsPhone);
        const notExpired = !dbSess?.expires_at || new Date(dbSess.expires_at).getTime() >= Date.now();
        if (canAutoStartOwner(owner) && notExpired) {
          sessionIdsToRestore.add(folder);
        }
      }
    });

    // Deduplicate candidate session IDs by (owner.id, phone) so we NEVER launch two sockets for the same WhatsApp number
    const dedupedByOwnerPhone = new Map<string, string>();
    for (const sid of sessionIdsToRestore) {
      const dbSess = getSessionById(sid);
      const phone = normalizePhoneNumber(dbSess?.phone_number || getCredsPhoneOnDisk(sid) || '');
      const owner = resolveActiveVerifiedOwner(sid, dbSess?.user_id, phone);
      if (!owner) continue;
      const dedupKey = phone ? `${owner.id}:${phone}` : sid;
      const existingSid = dedupedByOwnerPhone.get(dedupKey);
      if (!existingSid) {
        dedupedByOwnerPhone.set(dedupKey, sid);
      } else {
        const existingIsDb = Boolean(getSessionById(existingSid));
        const currentIsDb = Boolean(dbSess);
        if (!existingIsDb && currentIsDb) {
          dedupedByOwnerPhone.set(dedupKey, sid);
        }
      }
    }
    const finalSessionIdsToRestore = Array.from(dedupedByOwnerPhone.values());
    for (const sid of finalSessionIdsToRestore) {
      const dbSess = getSessionById(sid);
      const phone = normalizePhoneNumber(dbSess?.phone_number || getCredsPhoneOnDisk(sid) || '');
      const owner = resolveActiveVerifiedOwner(sid, dbSess?.user_id, phone);
      if (owner && phone) {
        cleanupDuplicateSessionsForOwnerPhone(sid, owner.id, phone);
      }
    }

    console.log(
      `[Baileys Persistent Storage] Found ${finalSessionIdsToRestore.length} active WhatsApp session(s) to restore.`
    );

    // Notify owners only for genuinely broken/expired sessions
    for (const s of dbSessions) {
      if (s.id && s.status === 'connected' && !finalSessionIdsToRestore.includes(s.id)) {
        updateSession(s.id, { status: 'disconnected' });
        const owner = resolveActiveVerifiedOwner(s.id, s.user_id, s.phone_number);
        if (!isOwnerActiveAndRegistered(owner)) continue;
        const isExpiredByDate = Boolean(s.expires_at && new Date(s.expires_at).getTime() < Date.now());
        await notifyUserSessionExpired({
          sessionId: s.id,
          sessionName: s.session_name,
          expiredPhone: s.phone_number,
          userId: owner!.id,
          reason: isExpiredByDate
            ? 'masa aktif sesi berakhir saat aplikasi di-restart'
            : 'kredensial login tidak ditemukan setelah build/restart server'
        }).catch(() => {});
      }
    }

    for (const sid of finalSessionIdsToRestore) {
      const existing = activeSessions.get(sid);
      if (!existing || existing.status !== 'connected' || !isSocketTrulyOpen(existing.socket)) {
        try {
          console.log(`[Baileys Auto-Restore] Rehydrating session: ${sid}...`);
          const dbSess = getSessionById(sid);
          await getOrStartBaileysSession(sid, dbSess?.phone_number, dbSess?.user_id);
          await delay(250);
        } catch (err) {
          console.error(`[Baileys Auto-Restore Error] Failed to restore session ${sid}:`, err);
        }
      }
    }
  } catch (err) {
    console.error('[Baileys Restore Error]', err);
  } finally {
    isRestoringSessions = false;
  }
}

export async function runBaileysPeriodicHealthCheck(): Promise<{
  checked: number;
  healed: number;
  notified: number;
}> {
  const now = Date.now();
  let checked = 0;
  let healed = 0;
  let notified = 0;

  cleanupExpiredCommandStates(now);
  if (recentBotOutgoingTexts.size > 0) {
    for (const [k, time] of recentBotOutgoingTexts.entries()) {
      if (now - time > 45000) recentBotOutgoingTexts.delete(k);
    }
  }

  await pruneInactiveAndUnregisteredBaileysSessions();

  const dbSessions = getWhatsAppSessions();
  for (const s of dbSessions) {
    if (!s.id || s.status !== 'connected') continue;
    if (s.expires_at && new Date(s.expires_at).getTime() < now) continue;
    checked++;

    const mem = activeSessions.get(s.id);
    if (mem && mem.status === 'connected' && isSocketTrulyOpen(mem.socket)) {
      continue;
    }

    if (reconnectTimers.has(s.id) || sessionStartLocks.has(s.id)) {
      continue;
    }

    const isConnectingRecently =
      mem && mem.status === 'connecting' && now - mem.lastUpdated < 60000;
    if (isConnectingRecently) continue;

    const owner = resolveActiveVerifiedOwner(s.id, s.user_id, s.phone_number);
    if (!isOwnerActiveAndRegistered(owner)) continue;

    let hasCreds = hasRegisteredCredsOnDisk(s.id);
    if (!hasCreds) {
      hasCreds = await hydrateSessionAuthFolderFromMysql(s.id).catch(() => false);
    }

    if (!hasCreds) {
      updateSession(s.id, { status: 'disconnected' });
      const alertRes = await notifyUserSessionExpired({
        sessionId: s.id,
        sessionName: s.session_name,
        expiredPhone: s.phone_number,
        userId: owner!.id,
        reason: 'kredensial login WhatsApp sudah tidak valid atau terputus'
      }).catch(() => ({ notified: false }));
      if (alertRes.notified) notified++;
      continue;
    }

    if (
      mem &&
      mem.status === 'disconnected' &&
      mem.disconnectedSince &&
      now - mem.disconnectedSince >= 5 * 60 * 1000
    ) {
      const alertRes = await notifyUserSessionExpired({
        sessionId: s.id,
        sessionName: s.session_name,
        expiredPhone: s.phone_number,
        userId: owner!.id,
        reason: 'koneksi WhatsApp terputus lebih dari 5 menit dan gagal pulih otomatis'
      }).catch(() => ({ notified: false }));
      if (alertRes.notified) notified++;
    }

    console.log(
      `[Baileys Watchdog] Auto-healing session ${s.id} (${s.phone_number || 'active'})...`
    );
    healed++;
    getOrStartBaileysSession(s.id, s.phone_number, owner!.id || s.user_id).catch(() => {});
  }

  if (getSuperadminWaQueue().length > 0 && resolveConnectedSuperadminSession()) {
    drainSuperadminWaQueue('watchdog').catch(() => {});
  }

  const pendingRes = await processPendingSessionExpiryAlerts('watchdog').catch(() => ({
    checked: 0,
    sent: 0,
    cancelled: 0,
    waiting: 0
  }));
  notified += pendingRes.sent;

  return { checked, healed, notified };
}

// Background Keep-Alive, Auto-Heal, Expiry Check & Notification Watchdog (every 25s like sendwa)
const baileysWatchdogTimer = setInterval(() => {
  runBaileysPeriodicHealthCheck().catch(() => {});
}, 25000);
baileysWatchdogTimer.unref?.();

export function shutdownBaileysManager(): void {
  clearInterval(baileysWatchdogTimer);
  for (const sid of Array.from(authBackupTimers.keys())) {
    clearSessionTimers(sid);
  }
  for (const sid of Array.from(reconnectTimers.keys())) {
    clearSessionTimers(sid);
  }
  for (const [sid, sessionData] of activeSessions.entries()) {
    try {
      sessionData.socket?.ev?.removeAllListeners?.('connection.update');
      sessionData.socket?.ev?.removeAllListeners?.('creds.update');
      sessionData.socket?.ev?.removeAllListeners?.('messages.upsert');
      sessionData.socket?.ev?.removeAllListeners?.('messages.update');
      sessionData.socket?.end?.(undefined);
      sessionData.socket?.ws?.removeAllListeners?.();
      try {
        sessionData.socket?.ws?.on?.('error', () => {});
      } catch {}
    } catch {
      // Ignore shutdown socket errors
    }
    sessionData.detachRawHandlers?.();
    clearMetaAiSession(sid);
  }
  activeSessions.clear();
  sessionStartLocks.clear();
  lastAuthBackupAt.clear();
  lastAuthBackupHashes.clear();
  commandState.clear();
  processedMessageIds.clear();
  recentBotOutgoingTexts.clear();
  incomingChatQueues.clear();
  for (const sid of Array.from(sessionUserDevicesCaches.keys())) {
    clearSessionCacheStores(sid);
  }
}

async function resolveTargetSessionForOutgoing(
  idOrPhone: string,
  options?: { userId?: string; allowAdminFallback?: boolean }
): Promise<{ targetSession: SessionState; sessionUserId?: string }> {
  const db = initDbFile();

  const resolvedDbById = idOrPhone ? getSessionById(idOrPhone) : null;
  const targetUserId =
    options?.userId ||
    resolvedDbById?.user_id ||
    (idOrPhone ? extractUserIdFromSessionId(idOrPhone, db.users) : undefined);

  const belongsToTargetUser = (s: { sessionId?: string; id?: string; userId?: string; user_id?: string }) => {
    if (!targetUserId) return true;
    const sid = s.sessionId || s.id || '';
    const uid = s.userId || s.user_id || '';
    return uid === targetUserId || (Boolean(sid) && isSessionOwnedByUserId(sid, targetUserId));
  };

  let targetSession: SessionState | undefined = idOrPhone ? activeSessions.get(idOrPhone) : undefined;
  if (targetSession && (!belongsToTargetUser(targetSession) || targetSession.status !== 'connected' || !isSocketTrulyOpen(targetSession.socket))) {
    targetSession = undefined;
  }

  if (!targetSession) {
    const cleanId = idOrPhone ? idOrPhone.replace(/\D/g, '') : '';
    for (const s of activeSessions.values()) {
      if (s.status === 'connected' && isSocketTrulyOpen(s.socket) && belongsToTargetUser(s)) {
        if (
          s.sessionId === idOrPhone ||
          (cleanId.length >= 8 && s.phoneNumber && normalizePhoneNumber(s.phoneNumber) === normalizePhoneNumber(cleanId))
        ) {
          targetSession = s;
          break;
        }
      }
    }
  }

  if (!targetSession && targetUserId) {
    const userConnected = Array.from(activeSessions.values()).filter(
      s => s.status === 'connected' && isSocketTrulyOpen(s.socket) && belongsToTargetUser(s)
    );
    targetSession = userConnected.find(s => s.is_primary) || userConnected[0];
  }

  if (!targetSession && (!targetUserId || options?.allowAdminFallback)) {
    const adminSysId = getPreferredSystemBaileysSessionId();
    if (adminSysId) {
      const candidate = activeSessions.get(adminSysId);
      if (candidate && candidate.status === 'connected' && isSocketTrulyOpen(candidate.socket)) {
        targetSession = candidate;
      }
    }
  }

  if (!targetSession) {
    const candidateFolders: string[] = [];
    const now = Date.now();
    const isNotExpiredSession = (sess: { expires_at?: string } | null | undefined) =>
      !sess?.expires_at || Date.parse(sess.expires_at) >= now;

    if (
      idOrPhone &&
      (!targetUserId || resolvedDbById?.user_id === targetUserId || isSessionOwnedByUserId(idOrPhone, targetUserId)) &&
      isNotExpiredSession(resolvedDbById)
    ) {
      candidateFolders.push(idOrPhone);
    }

    const userCandidateDb = [...db.sessions]
      .filter(s => s.id && belongsToTargetUser(s) && isNotExpiredSession(s))
      .sort((a, b) => Number(Boolean(b.is_primary)) - Number(Boolean(a.is_primary)));

    for (const s of userCandidateDb) {
      if (!candidateFolders.includes(s.id)) {
        candidateFolders.push(s.id);
      }
    }

    for (const folderId of candidateFolders) {
      let hasCreds = hasRegisteredCredsOnDisk(folderId);
      if (!hasCreds) {
        hasCreds = await hydrateSessionAuthFolderFromMysql(folderId).catch(() => false);
      }
      if (hasCreds) {
        console.log(`[Baileys Auto-Connect] Waking session "${folderId}" for outgoing Blast/API dispatch...`);
        const sessMeta = getSessionById(folderId);
        targetSession = await getOrStartBaileysSession(folderId, sessMeta?.phone_number, sessMeta?.user_id || targetUserId);
        let waitCount = 0;
        while (waitCount < 14 && targetSession && targetSession.status !== 'connected') {
          await delay(500);
          waitCount++;
        }
        if (targetSession && targetSession.status === 'connected' && isSocketTrulyOpen(targetSession.socket)) {
          targetSession.lastOutgoingAt = Date.now();
          break;
        }
        targetSession = undefined;
      }
    }

    if (!targetSession && targetUserId) {
      const fallbackEntry = await ensureConnectedSessionForUser(targetUserId, idOrPhone || undefined);
      if (fallbackEntry) {
        const mem = activeSessions.get(fallbackEntry.sessionId);
        if (mem && mem.status === 'connected' && isSocketTrulyOpen(mem.socket)) {
          mem.lastOutgoingAt = Date.now();
          targetSession = mem;
        }
      }
    }
  }

  if (!targetSession) {
    const connectingSession = Array.from(activeSessions.values()).find(
      s => s.status === 'connecting' && belongsToTargetUser(s)
    );
    if (connectingSession) {
      let waitRetry = 0;
      while (waitRetry < 10 && connectingSession.status === 'connecting') {
        await delay(500);
        waitRetry++;
      }
      if (connectingSession.status === 'connected' && isSocketTrulyOpen(connectingSession.socket)) {
        targetSession = connectingSession;
      }
    }
  }

  if (targetSession && targetSession.socket && isSocketTrulyOpen(targetSession.socket)) {
    const idleMs = Date.now() - Math.max(targetSession.lastUpdated || 0, targetSession.lastOutgoingAt || 0);
    if (idleMs > 25000 && typeof targetSession.socket.query === 'function') {
      try {
        await targetSession.socket.query(
          {
            tag: 'iq',
            attrs: { to: 's.whatsapp.net', type: 'get', xmlns: 'w:p' },
            content: [{ tag: 'ping', attrs: {} }]
          },
          2500
        );
        targetSession.lastUpdated = Date.now();
      } catch {
        console.warn(`[Baileys Liveness Probe] Socket idle >25s (${targetSession.sessionId}) tidak merespons ping; menyambung ulang cepat...`);
        const refreshed = await getOrStartBaileysSession(
          targetSession.sessionId,
          targetSession.phoneNumber || undefined,
          targetSession.userId,
          { forceReconnect: true }
        ).catch(() => null);
        if (refreshed) {
          let waitIdx = 0;
          while (waitIdx < 16 && refreshed.status !== 'connected') {
            await delay(250);
            waitIdx++;
          }
          if (refreshed.status === 'connected' && isSocketTrulyOpen(refreshed.socket)) {
            targetSession = refreshed;
          }
        }
      }
    }
  }

  if (!targetSession || !targetSession.socket || targetSession.status !== 'connected' || !isSocketTrulyOpen(targetSession.socket)) {
    throw new Error('Gagal terhubung ke WhatsApp Sesi milik akun ini. Pastikan nomor WhatsApp Anda sudah terhubung (Scan QR / Kode Pairing) di menu Koneksi WA.');
  }

  targetSession.lastOutgoingAt = Date.now();

  const sessionUserId =
    targetUserId ||
    targetSession.userId ||
    extractUserIdFromSessionId(targetSession.sessionId, db.users);

  return { targetSession, sessionUserId };
}

export interface BaileysMediaPayload {
  mediaType: 'image' | 'document' | 'video' | 'audio';
  mediaBuffer?: Buffer;
  mediaUrl?: string;
  mimetype?: string;
  fileName?: string;
  caption?: string;
  text?: string;
  sendTextSeparately?: boolean;
}

export async function sendBaileysMediaMessage(
  idOrPhone: string,
  recipientPhone: string,
  payload: BaileysMediaPayload,
  options?: { userId?: string; isBroadcast?: boolean; skipLog?: boolean; skipQuota?: boolean; allowAdminFallback?: boolean }
) {
  const cleanRecipient = normalizePhoneNumber(recipientPhone);
  if (!cleanRecipient || cleanRecipient.length < 8) {
    throw new Error(`Nomor WhatsApp tujuan tidak valid (${recipientPhone}).`);
  }

  const jid = `${cleanRecipient}@s.whatsapp.net`;
  let { targetSession, sessionUserId } = await resolveTargetSessionForOutgoing(idOrPhone, options);

  const mediaData: any = payload.mediaBuffer
    ? payload.mediaBuffer
    : payload.mediaUrl
      ? { url: payload.mediaUrl }
      : null;

  if (!mediaData) {
    throw new Error('Konten media atau dokumen kosong.');
  }

  const standaloneText = payload.text ? String(payload.text).trim() : '';
  const captionText = payload.caption ? String(payload.caption).trim() : '';

  const buildBaileysContent = () => {
    if (payload.mediaType === 'image') {
      return {
        image: mediaData,
        ...(captionText ? { caption: captionText } : {}),
        ...(payload.mimetype ? { mimetype: payload.mimetype } : {})
      };
    }
    if (payload.mediaType === 'video') {
      return {
        video: mediaData,
        ...(captionText ? { caption: captionText } : {}),
        ...(payload.mimetype ? { mimetype: payload.mimetype } : {})
      };
    }
    if (payload.mediaType === 'audio') {
      return {
        audio: mediaData,
        mimetype: payload.mimetype || 'audio/mpeg',
        ptt: false
      };
    }
    return {
      document: mediaData,
      mimetype: payload.mimetype || 'application/pdf',
      fileName: payload.fileName || 'document.pdf',
      ...(captionText ? { caption: captionText } : {})
    };
  };

  const logPreview =
    [
      standaloneText || '',
      `[${payload.mediaType.toUpperCase()}${payload.fileName ? `: ${payload.fileName}` : ''}]`,
      captionText || ''
    ]
      .filter(Boolean)
      .join(' ')
      .slice(0, 1000);

  console.log(`[Baileys Outgoing Media:${payload.mediaType}] Sending to ${jid} via session ${targetSession.sessionId}...`);

  let result: any = null;
  try {
    if (typeof targetSession.socket?.sendPresenceUpdate === 'function') {
      void Promise.race([
        Promise.resolve().then(() => targetSession.socket.sendPresenceUpdate('composing', jid)),
        delay(800)
      ]).catch(() => {});
    }

    if (standaloneText && (payload.sendTextSeparately || captionText || payload.mediaType === 'audio')) {
      recordBotOutgoing(standaloneText);
      await sendSocketMessageWithAckGuard(
        targetSession.socket,
        jid,
        { text: standaloneText },
        { timeoutMs: 24000, sessionData: targetSession }
      );
      await delay(300);
    }

    if (captionText) recordBotOutgoing(captionText);
    result = await sendSocketMessageWithAckGuard(
      targetSession.socket,
      jid,
      buildBaileysContent(),
      { timeoutMs: 32000, sessionData: targetSession }
    );
  } catch (firstErr: any) {
    const errMsg = String(firstErr?.message || '');
    const isSocketDrop = /closed|terputus|connection/i.test(errMsg);
    if (!isSocketDrop) {
      if (!options?.skipLog) {
        addMessageLog({
          wam_id: `baileys_fail_${Date.now()}`,
          session_id: targetSession.sessionId,
          user_id: sessionUserId,
          sender_phone: cleanRecipient,
          sender_name: options?.isBroadcast ? `Broadcast (${cleanRecipient})` : `Tujuan (${cleanRecipient})`,
          message_body: logPreview,
          direction: 'outgoing',
          status: 'Gagal',
          error_detail: errMsg || 'Gagal mengirim media/dokumen'
        });
      }
      throw firstErr;
    }

    console.warn(`[Baileys Outgoing Media Reconnect] Socket terputus (${errMsg}), menyambung ulang sekali...`);
    await delay(600);
    const refreshed = activeSessions.get(targetSession.sessionId);
    if (!refreshed || !refreshed.socket || refreshed.status !== 'connected' || !isSocketTrulyOpen(refreshed.socket)) {
      if (!options?.skipLog) {
        addMessageLog({
          wam_id: `baileys_fail_${Date.now()}`,
          session_id: targetSession.sessionId,
          user_id: sessionUserId,
          sender_phone: cleanRecipient,
          sender_name: options?.isBroadcast ? `Broadcast (${cleanRecipient})` : `Tujuan (${cleanRecipient})`,
          message_body: logPreview,
          direction: 'outgoing',
          status: 'Gagal',
          error_detail: errMsg || 'Koneksi terputus saat kirim media'
        });
      }
      throw firstErr;
    }
    targetSession = refreshed;
    try {
      result = await sendSocketMessageWithAckGuard(
        targetSession.socket,
        jid,
        buildBaileysContent(),
        { timeoutMs: 32000, sessionData: targetSession }
      );
    } catch (retryErr: any) {
      if (!options?.skipLog) {
        addMessageLog({
          wam_id: `baileys_fail_${Date.now()}`,
          session_id: targetSession.sessionId,
          user_id: sessionUserId,
          sender_phone: cleanRecipient,
          sender_name: options?.isBroadcast ? `Broadcast (${cleanRecipient})` : `Tujuan (${cleanRecipient})`,
          message_body: logPreview,
          direction: 'outgoing',
          status: 'Gagal',
          error_detail: retryErr?.message || 'Gagal mengirim media/dokumen setelah percobaan ulang'
        });
      }
      throw retryErr;
    }
  }

  if (!options?.skipLog) {
    addMessageLog({
      wam_id: result?.key?.id || `baileys_${Date.now()}`,
      session_id: targetSession.sessionId,
      user_id: sessionUserId,
      sender_phone: cleanRecipient,
      sender_name: options?.isBroadcast ? `Broadcast (${cleanRecipient})` : `Tujuan (${cleanRecipient})`,
      message_body: logPreview,
      direction: 'outgoing',
      status: 'Sukses',
      reply_body: logPreview
    });
  }

  targetSession.lastOutgoingAt = Date.now();

  if (!options?.skipQuota && sessionUserId) {
    deductUserDailyQuota(sessionUserId);
  }

  return {
    success: true,
    wam_id: result?.key?.id,
    to: cleanRecipient,
    session_id: targetSession.sessionId,
    media_type: payload.mediaType,
    raw: result
  };
}

// Send actual outgoing WhatsApp message via connected Baileys socket with strict multi-tenant isolation
export async function sendBaileysTextMessage(
  idOrPhone: string,
  recipientPhone: string,
  text: string,
  options?: { userId?: string; isBroadcast?: boolean; skipLog?: boolean; skipQuota?: boolean; allowAdminFallback?: boolean }
) {
  const cleanRecipient = normalizePhoneNumber(recipientPhone);
  if (!cleanRecipient || cleanRecipient.length < 8) {
    throw new Error(`Nomor WhatsApp tujuan tidak valid (${recipientPhone}).`);
  }

  const jid = `${cleanRecipient}@s.whatsapp.net`;
  let { targetSession, sessionUserId } = await resolveTargetSessionForOutgoing(idOrPhone, options);

  console.log(`[Baileys Outgoing] Sending message to ${jid} via session ${targetSession.sessionId}...`);
  recordBotOutgoing(text);

  let result: any = null;
  try {
    if (typeof targetSession.socket?.sendPresenceUpdate === 'function') {
      void Promise.race([
        Promise.resolve().then(() => targetSession.socket.sendPresenceUpdate('composing', jid)),
        delay(800)
      ]).catch(() => {});
    }
    result = await sendSocketMessageWithAckGuard(
      targetSession.socket,
      jid,
      { text },
      { timeoutMs: 24000, sessionData: targetSession }
    );
  } catch (firstErr: any) {
    const errMsg = String(firstErr?.message || '');
    const isSocketDrop = /closed|terputus|connection/i.test(errMsg);
    if (!isSocketDrop) {
      if (!options?.skipLog) {
        addMessageLog({
          wam_id: `baileys_fail_${Date.now()}`,
          session_id: targetSession.sessionId,
          user_id: sessionUserId,
          sender_phone: cleanRecipient,
          sender_name: options?.isBroadcast ? `Broadcast (${cleanRecipient})` : `Tujuan (${cleanRecipient})`,
          message_body: text,
          direction: 'outgoing',
          status: 'Gagal',
          error_detail: errMsg || 'Gagal mengirim pesan WhatsApp'
        });
      }
      throw firstErr;
    }

    console.warn(`[Baileys Outgoing Reconnect] Socket terputus (${errMsg}), mencoba ulang sekali setelah 600ms...`);
    await delay(600);
    const refreshed = activeSessions.get(targetSession.sessionId);
    if (!refreshed || !refreshed.socket || refreshed.status !== 'connected' || !isSocketTrulyOpen(refreshed.socket)) {
      if (!options?.skipLog) {
        addMessageLog({
          wam_id: `baileys_fail_${Date.now()}`,
          session_id: targetSession.sessionId,
          user_id: sessionUserId,
          sender_phone: cleanRecipient,
          sender_name: options?.isBroadcast ? `Broadcast (${cleanRecipient})` : `Tujuan (${cleanRecipient})`,
          message_body: text,
          direction: 'outgoing',
          status: 'Gagal',
          error_detail: errMsg || 'Koneksi terputus saat mengirim pesan'
        });
      }
      throw firstErr;
    }
    targetSession = refreshed;
    try {
      result = await sendSocketMessageWithAckGuard(
        targetSession.socket,
        jid,
        { text },
        { timeoutMs: 24000, sessionData: targetSession }
      );
    } catch (retryErr: any) {
      if (!options?.skipLog) {
        addMessageLog({
          wam_id: `baileys_fail_${Date.now()}`,
          session_id: targetSession.sessionId,
          user_id: sessionUserId,
          sender_phone: cleanRecipient,
          sender_name: options?.isBroadcast ? `Broadcast (${cleanRecipient})` : `Tujuan (${cleanRecipient})`,
          message_body: text,
          direction: 'outgoing',
          status: 'Gagal',
          error_detail: retryErr?.message || 'Gagal mengirim pesan setelah percobaan ulang'
        });
      }
      throw retryErr;
    }
  }

  if (!options?.skipLog) {
    addMessageLog({
      wam_id: result?.key?.id || `baileys_${Date.now()}`,
      session_id: targetSession.sessionId,
      user_id: sessionUserId,
      sender_phone: cleanRecipient,
      sender_name: options?.isBroadcast ? `Broadcast (${cleanRecipient})` : `Tujuan (${cleanRecipient})`,
      message_body: text,
      direction: 'outgoing',
      status: 'Sukses',
      reply_body: options?.isBroadcast ? 'Dikirim via Broadcast Massal' : text
    });
  }

  targetSession.lastOutgoingAt = Date.now();

  if (!options?.skipQuota && sessionUserId) {
    deductUserDailyQuota(sessionUserId);
  }

  return {
    success: true,
    wam_id: result?.key?.id,
    to: cleanRecipient,
    session_id: targetSession.sessionId,
    raw: result
  };
}

// =========================================================================
// SUPERADMIN WHATSAPP DIRECT DISPATCH + PERSISTENT SLOW QUEUE DRAIN
// =========================================================================
let isDrainingSuperadminQueue = false;

function resolveConnectedSuperadminSession(): SessionState | null {
  const isAdminSession = (s: SessionState) => {
    if (s.status !== 'connected' || !s.socket || !isSocketTrulyOpen(s.socket)) return false;
    const ownerId = s.userId || getSessionById(s.sessionId)?.user_id;
    const owner = ownerId ? getUserById(ownerId) : null;
    return Boolean(owner && owner.role === 'admin' && owner.is_active);
  };

  const candidates = Array.from(activeSessions.values()).filter(isAdminSession);
  if (candidates.length === 0) return null;
  return candidates.find(s => s.is_primary) || candidates[0];
}

async function sendDirectlyViaSuperadminSocket(
  saSession: SessionState,
  recipientPhone: string,
  text: string
): Promise<string | undefined> {
  const cleanRecipient = normalizePhoneNumber(recipientPhone);
  if (!cleanRecipient || cleanRecipient.length < 8) {
    throw new Error(`Nomor WhatsApp tujuan tidak valid (${recipientPhone}).`);
  }
  const jid = `${cleanRecipient}@s.whatsapp.net`;
  recordBotOutgoing(text);

  if (typeof saSession.socket?.sendPresenceUpdate === 'function') {
    void Promise.race([Promise.resolve().then(() => saSession.socket.sendPresenceUpdate('composing', jid)), delay(800)]).catch(() => {});
  }

  const result: any = await sendSocketMessageWithAckGuard(
    saSession.socket,
    jid,
    { text },
    { timeoutMs: 24000, sessionData: saSession }
  );
  return result?.key?.id;
}

export async function sendOrQueueViaSuperadminWa(params: {
  recipientPhone: string;
  message: string;
  category: 'order_notification' | 'password_reset' | 'system_otp' | 'session_expired';
  ownerUserId?: string;
  invoiceNumber?: string;
}): Promise<{
  sent: boolean;
  queued: boolean;
  queueId?: string;
  sessionId?: string;
  error?: string;
}> {
  const cleanRecipient = normalizePhoneNumber(params.recipientPhone);
  if (!cleanRecipient || cleanRecipient.length < 8) {
    return {
      sent: false,
      queued: false,
      error: `Nomor WhatsApp tujuan tidak valid (${params.recipientPhone || '-'}).`
    };
  }

  let saSession = resolveConnectedSuperadminSession();

  // If a superadmin session is currently mid-handshake/reconnecting, wait up to 3s once
  if (!saSession) {
    const adminConnecting = Array.from(activeSessions.values()).find(s => {
      if (s.status !== 'connecting') return false;
      const ownerId = s.userId || getSessionById(s.sessionId)?.user_id;
      const owner = ownerId ? getUserById(ownerId) : null;
      return Boolean(owner && owner.role === 'admin' && owner.is_active);
    });
    if (adminConnecting) {
      let tries = 0;
      while (tries < 6 && adminConnecting.status === 'connecting') {
        await delay(500);
        tries++;
      }
      saSession = resolveConnectedSuperadminSession();
    }
  }

  if (saSession) {
    try {
      await sendDirectlyViaSuperadminSocket(saSession, cleanRecipient, params.message);
      console.log(
        `[Superadmin WA Direct] (${params.category}) Sent to ${cleanRecipient} via ${saSession.sessionId}`
      );
      if (params.category === 'order_notification' && params.ownerUserId) {
        addMessageLog({
          wam_id: `sa_ord_${Date.now()}`,
          session_id: saSession.sessionId,
          user_id: params.ownerUserId,
          sender_phone: cleanRecipient,
          sender_name: `Owner Usaha (${cleanRecipient})`,
          message_body: `[Notifikasi Order ${params.invoiceNumber || ''}] Dikirim oleh Superadmin WA`.trim(),
          direction: 'outgoing',
          status: 'Sukses',
          reply_body: params.message.slice(0, 1200)
        });
      }
      return { sent: true, queued: false, sessionId: saSession.sessionId };
    } catch (err: any) {
      console.warn(
        `[Superadmin WA Queue Fallback] Gagal kirim langsung (${params.category}) ke ${cleanRecipient}: ${err?.message}. Memasukkan ke antrean...`
      );
      const queuedEntry = enqueueSuperadminWaMessage({
        recipient_phone: cleanRecipient,
        message: params.message,
        category: params.category,
        owner_user_id: params.ownerUserId,
        invoice_number: params.invoiceNumber,
        last_error: err?.message || 'Gagal kirim langsung'
      });
      return { sent: false, queued: true, queueId: queuedEntry.id, error: err?.message };
    }
  }

  const queuedEntry = enqueueSuperadminWaMessage({
    recipient_phone: cleanRecipient,
    message: params.message,
    category: params.category,
    owner_user_id: params.ownerUserId,
    invoice_number: params.invoiceNumber,
    last_error: 'WhatsApp Superadmin belum terhubung'
  });
  console.log(
    `[Superadmin WA Queued] (${params.category}) Ditambahkan ke antrean untuk ${cleanRecipient} (ID: ${queuedEntry.id})`
  );
  return { sent: false, queued: true, queueId: queuedEntry.id };
}

export async function drainSuperadminWaQueue(
  reason = 'manual'
): Promise<{ processed: number; sent: number; failed: number; remaining: number }> {
  if (isDrainingSuperadminQueue) {
    return { processed: 0, sent: 0, failed: 0, remaining: getSuperadminWaQueue().length };
  }

  const initialQueue = getSuperadminWaQueue();
  if (initialQueue.length === 0) {
    return { processed: 0, sent: 0, failed: 0, remaining: 0 };
  }

  if (!resolveConnectedSuperadminSession()) {
    return { processed: 0, sent: 0, failed: 0, remaining: initialQueue.length };
  }

  isDrainingSuperadminQueue = true;
  let processed = 0;
  let sent = 0;
  let failed = 0;

  try {
    console.log(
      `[Superadmin WA Queue Drain:${reason}] Memproses ${initialQueue.length} pesan antrean secara perlahan (anti-ban)...`
    );

    for (let i = 0; i < initialQueue.length; i++) {
      const item = initialQueue[i];
      const liveSa = resolveConnectedSuperadminSession();
      if (!liveSa) {
        console.warn('[Superadmin WA Queue Drain] Koneksi WA Superadmin terputus saat menguras antrean; sisa pesan ditahan.');
        break;
      }

      processed++;
      try {
        if (item.category === 'session_expired' && item.owner_user_id) {
          const sidFromInvoice = item.invoice_number?.startsWith(`exp_${item.owner_user_id}_`)
            ? item.invoice_number.slice(`exp_${item.owner_user_id}_`.length)
            : '';
          const stateCheck = verifyExpiredAlertState({
            userId: item.owner_user_id,
            sessionId: sidFromInvoice,
            expiredPhone: sidFromInvoice
          });
          if (stateCheck === 'recovered') {
            removeSuperadminWaQueueItem(item.id);
            continue;
          }
          if (stateCheck === 'wait') {
            continue;
          }
        }

        await sendDirectlyViaSuperadminSocket(liveSa, item.recipient_phone, item.message);
        removeSuperadminWaQueueItem(item.id);
        sent++;
        console.log(
          `[Superadmin WA Queue Drain] Terkirim (${i + 1}/${initialQueue.length}) -> ${item.recipient_phone} [${item.category}]`
        );

        if (item.category === 'order_notification' && item.owner_user_id) {
          addMessageLog({
            wam_id: `sa_qord_${Date.now()}`,
            session_id: liveSa.sessionId,
            user_id: item.owner_user_id,
            sender_phone: item.recipient_phone,
            sender_name: `Owner Usaha (${item.recipient_phone})`,
            message_body: `[Notifikasi Order Antrean ${item.invoice_number || ''}] Dikirim oleh Superadmin WA`.trim(),
            direction: 'outgoing',
            status: 'Sukses',
            reply_body: item.message.slice(0, 1200)
          });
        }
      } catch (sendErr: any) {
        failed++;
        const nextAttempts = (item.attempts || 0) + 1;
        if (nextAttempts >= 8) {
          console.warn(
            `[Superadmin WA Queue Drain] Menghapus item antrean ${item.id} setelah ${nextAttempts}x gagal (${sendErr?.message}).`
          );
          removeSuperadminWaQueueItem(item.id);
        } else {
          updateSuperadminWaQueueItem(item.id, {
            attempts: nextAttempts,
            last_error: sendErr?.message || 'Gagal kirim dari antrean'
          });
        }
      }

      // Slow randomized delay (3.5s - 6s) between queued dispatches so Meta won't flag spam
      if (i < initialQueue.length - 1) {
        const slowPaceMs = 3500 + crypto.randomInt(0, 2500);
        await delay(slowPaceMs);
      }
    }
  } finally {
    isDrainingSuperadminQueue = false;
  }

  return {
    processed,
    sent,
    failed,
    remaining: getSuperadminWaQueue().length
  };
}

