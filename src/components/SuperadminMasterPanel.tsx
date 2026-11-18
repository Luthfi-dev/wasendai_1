import React, { useState, useEffect } from 'react';
import { apiFetch } from '../lib/csrfFetch';
import {
  ShieldAlert,
  Lock,
  Unlock,
  Key,
  Sliders,
  Settings,
  Plus,
  Trash2,
  Edit2,
  CheckCircle2,
  AlertTriangle,
  Sparkles,
  QrCode,
  Upload,
  RefreshCw,
  Eye,
  EyeOff,
  Building,
  Smartphone,
  Check,
  X,
  Layers,
  Flame,
  Globe,
  Mail,
  Send
} from 'lucide-react';
import { SubscriptionPlan, AppWhitelabelConfig, QrisConfig, SmtpAccount, GlobalSlotStatus } from '../types/whatsapp';
import { ConfirmModal } from './ConfirmModal';
import { DEFAULT_PUBLIC_LOGO_URL, resolveLogoUrl, handleLogoImgError } from '../lib/branding';

interface SuperadminMasterPanelProps {
  onWhitelabelUpdated?: (whitelabel: AppWhitelabelConfig) => void;
  onPlansUpdated?: (plans: SubscriptionPlan[]) => void;
  onQrisUpdated?: (qris: QrisConfig) => void;
}

export const SuperadminMasterPanel: React.FC<SuperadminMasterPanelProps> = ({
  onWhitelabelUpdated,
  onPlansUpdated,
  onQrisUpdated
}) => {
  // Master PIN Unlock State
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [pinInput, setPinInput] = useState('');
  const [pinError, setPinError] = useState('');
  const [isVerifyingPin, setIsVerifyingPin] = useState(false);

  // Active Sub-Tab
  const [activeTab, setActiveTab] = useState<'plans' | 'whitelabel' | 'smtp' | 'gemini' | 'qris'>('plans');
  const [toastMsg, setToastMsg] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, keyName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(keyName);
    showToast('Berhasil disalin ke clipboard!');
    setTimeout(() => setCopiedKey(null), 2500);
  };

  // Plans State
  const [plans, setPlans] = useState<SubscriptionPlan[]>([]);
  const [editingPlan, setEditingPlan] = useState<SubscriptionPlan | null>(null);
  const [showPlanModal, setShowPlanModal] = useState(false);
  const [isSavingPlan, setIsSavingPlan] = useState(false);
  const [maxGlobalSessions, setMaxGlobalSessions] = useState<string>('10');
  const [slotStatus, setSlotStatus] = useState<GlobalSlotStatus | null>(null);
  const [isSavingMaxGlobal, setIsSavingMaxGlobal] = useState(false);

  // Whitelabel State
  const [whitelabel, setWhitelabel] = useState<AppWhitelabelConfig>({
    app_name: 'Japriin Pro',
    tagline: 'Whitelabel WhatsApp Gateway, REST API & Remote AI Bot',
    logo_url: DEFAULT_PUBLIC_LOGO_URL,
    company_name: 'PT Japriin Teknologi Indonesia',
    support_phone: '081234567890',
    primary_bot_phone: '081234567890',
    primary_bot_name: 'Japriin Assistant Pusat',
    footer_text: 'Dikelola secara profesional oleh Japriin.com',
    api_enabled: true
  });
  const [isSavingWhitelabel, setIsSavingWhitelabel] = useState(false);

  // Meta AI WhatsApp (Baileys) Status State
  const [metaAiSessions, setMetaAiSessions] = useState<Array<{ sessionId: string; userId: string; phoneNumber: string }>>([]);
  const [metaAiJid, setMetaAiJid] = useState('13135550002@s.whatsapp.net');
  const [isTestingMetaAi, setIsTestingMetaAi] = useState(false);
  const [metaAiTestResult, setMetaAiTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [aiAuditLogs, setAiAuditLogs] = useState<Array<{
    timestamp: string;
    level: 'INFO' | 'WARN' | 'ERROR';
    stage: string;
    session_id?: string;
    user_id?: string;
    customer_code?: string;
    sender_masked?: string;
    error_code?: string;
    reason: string;
    latency_ms?: number;
  }>>([]);
  const [aiAuditLogFile, setAiAuditLogFile] = useState('logs/meta-ai-audit.log');
  const [aiAuditLevelFilter, setAiAuditLevelFilter] = useState<'ALL' | 'ERROR' | 'WARN' | 'INFO'>('ALL');
  const [isLoadingAuditLogs, setIsLoadingAuditLogs] = useState(false);

  // Multi-SMTP State
  const [smtpList, setSmtpList] = useState<SmtpAccount[]>([]);
  const [newSmtpName, setNewSmtpName] = useState('');
  const [newSmtpHost, setNewSmtpHost] = useState('smtp.gmail.com');
  const [newSmtpPort, setNewSmtpPort] = useState(587);
  const [newSmtpSecure, setNewSmtpSecure] = useState(false);
  const [newSmtpUser, setNewSmtpUser] = useState('');
  const [newSmtpSenderName, setNewSmtpSenderName] = useState('');
  const [newSmtpPass, setNewSmtpPass] = useState('');
  const [isAddingSmtp, setIsAddingSmtp] = useState(false);
  const [testingSmtpId, setTestingSmtpId] = useState<string | null>(null);
  const [editingSmtp, setEditingSmtp] = useState<{
    id: string;
    name: string;
    host: string;
    port: number;
    secure: boolean;
    user: string;
    sender_name: string;
    pass: string;
    is_active: boolean;
  } | null>(null);
  const [isSavingEditSmtp, setIsSavingEditSmtp] = useState(false);
  const [testEmailRecipient, setTestEmailRecipient] = useState('');
  const [isSendingTestEmail, setIsSendingTestEmail] = useState(false);
  const [smtpErrorMsg, setSmtpErrorMsg] = useState('');

  // QRIS State
  const [qrisConfig, setQrisConfig] = useState<QrisConfig>({
    image_url: '',
    account_name: 'PT JAPRIIN MEDIA TEKNOLOGI',
    bank_name: 'QRIS ALL PAYMENT & BCA',
    account_number: '123-456-7890',
    instructions: 'Scan QRIS atau transfer BCA lalu upload bukti transfer.'
  });
  const [isSavingQris, setIsSavingQris] = useState(false);

  // Confirm Modal
  const [confirmModal, setConfirmModal] = useState<{
    isOpen: boolean;
    title: string;
    message: string;
    onConfirm: () => void;
  }>({
    isOpen: false,
    title: '',
    message: '',
    onConfirm: () => {}
  });

  const fetchData = async (unlockedOverride?: boolean) => {
    try {
      const [pRes, wRes, qRes] = await Promise.all([
        apiFetch('/api/plans').then(r => r.json()).catch(() => ({ success: false })),
        apiFetch('/api/whitelabel').then(r => r.json()).catch(() => ({ success: false })),
        apiFetch('/api/qris').then(r => r.json()).catch(() => ({ success: false }))
      ]);

      if (pRes.success) {
        setPlans(pRes.data);
        if (typeof pRes.max_global_sessions === 'number' && Number.isFinite(pRes.max_global_sessions)) {
          setMaxGlobalSessions(String(pRes.max_global_sessions));
        }
        if (pRes.slot_status) {
          setSlotStatus(pRes.slot_status);
        }
      }
      if (wRes.success) setWhitelabel(wRes.data);
      if (qRes.success) setQrisConfig(qRes.data);

      const shouldFetchProtected = unlockedOverride !== undefined ? unlockedOverride : isUnlocked;
      if (shouldFetchProtected) {
        const [aiRes, sRes, auditRes] = await Promise.all([
          apiFetch('/api/ai/status').then(r => r.json()).catch(() => ({ success: false })),
          apiFetch('/api/smtp').then(r => r.json()).catch(() => ({ success: false })),
          apiFetch(`/api/admin/ai-audit-logs?limit=50&level=${aiAuditLevelFilter}`).then(r => r.json()).catch(() => ({ success: false }))
        ]);
        if (aiRes.success) {
          setMetaAiSessions(Array.isArray(aiRes.connected_sessions) ? aiRes.connected_sessions : []);
          if (aiRes.meta_ai_jid) setMetaAiJid(aiRes.meta_ai_jid);
        }
        if (sRes.success && sRes.data) setSmtpList(sRes.data);
        if (auditRes.success) {
          setAiAuditLogs(Array.isArray(auditRes.data) ? auditRes.data : []);
          if (auditRes.log_file) setAiAuditLogFile(auditRes.log_file);
        }
      }
    } catch {}
  };

  const handleRefreshAiAuditLogs = async (nextLevel: 'ALL' | 'ERROR' | 'WARN' | 'INFO' = aiAuditLevelFilter) => {
    setAiAuditLevelFilter(nextLevel);
    setIsLoadingAuditLogs(true);
    try {
      const res = await apiFetch(`/api/admin/ai-audit-logs?limit=50&level=${nextLevel}`);
      const data = await res.json();
      if (res.ok && data.success) {
        setAiAuditLogs(Array.isArray(data.data) ? data.data : []);
        if (data.log_file) setAiAuditLogFile(data.log_file);
      }
    } catch {} finally {
      setIsLoadingAuditLogs(false);
    }
  };

  useEffect(() => {
    apiFetch('/api/auth/master-status')
      .then(r => r.json())
      .then(st => {
        const unlocked = Boolean(st?.success && st?.unlocked);
        setIsUnlocked(unlocked);
        fetchData(unlocked);
      })
      .catch(() => {
        fetchData(false);
      });
  }, []);

  const handleUnlockMaster = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsVerifyingPin(true);
    setPinError('');

    try {
      const res = await apiFetch('/api/auth/master-pin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin: pinInput })
      });
      const data = await res.json();
      if (data.success) {
        setIsUnlocked(true);
        setPinInput('');
        fetchData(true);
      } else {
        setPinError(data.error || 'PIN Master Superadmin Salah!');
      }
    } catch (err) {
      setPinError('Gagal memverifikasi PIN.');
    } finally {
      setIsVerifyingPin(false);
    }
  };

  const showToast = (msg: string) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(''), 4000);
  };

  const handleSaveMaxGlobalSessions = async (e: React.FormEvent) => {
    e.preventDefault();
    const numericMax = Math.floor(Number(maxGlobalSessions));
    if (!Number.isFinite(numericMax) || numericMax < 1 || numericMax > 10000) {
      showToast('❌ Batas kapasitas harus bilangan bulat antara 1 hingga 10.000 sesi WA.');
      return;
    }
    setIsSavingMaxGlobal(true);
    try {
      const res = await apiFetch('/api/superadmin/max-sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ max_global_sessions: numericMax })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setMaxGlobalSessions(String(data.max_global_sessions));
        if (data.slot_status) setSlotStatus(data.slot_status);
        showToast(data.message || `✓ Batas maksimal nomor WhatsApp global diubah menjadi ${data.max_global_sessions} sesi!`);
      } else {
        showToast(`❌ ${data.error || 'Gagal menyimpan kapasitas maksimal sesi WhatsApp.'}`);
      }
    } catch {
      showToast('❌ Gagal menghubungi server.');
    } finally {
      setIsSavingMaxGlobal(false);
    }
  };

  // Plan Save Handler
  const handleSavePlan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingPlan) return;
    setIsSavingPlan(true);

    try {
      const isNew = !plans.some(p => p.id === editingPlan.id);
      const url = isNew ? '/api/plans' : `/api/plans/${editingPlan.id}`;
      const method = isNew ? 'POST' : 'PUT';

      const res = await apiFetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(editingPlan)
      });
      const data = await res.json();
      if (data.success) {
        showToast('✓ Paket langganan berhasil disimpan & langsung aktif!');
        setShowPlanModal(false);
        setEditingPlan(null);
        await fetchData();
        const freshPlans = await apiFetch('/api/plans').then(r => r.json()).catch(() => null);
        if (freshPlans?.success && freshPlans.data) {
          onPlansUpdated?.(freshPlans.data);
          window.dispatchEvent(new CustomEvent('plans-updated', { detail: freshPlans.data }));
        }
      }
    } catch (err) {
      showToast('Gagal menyimpan paket.');
    } finally {
      setIsSavingPlan(false);
    }
  };

  // Logo Upload Handler (auto-resize & compress so custom logos always fit safely under backend 500KB limit)
  const handleLogoImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.type.startsWith('image/')) {
      showToast('Pilih file gambar yang valid (PNG, JPG, WebP).');
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const rawDataUrl = reader.result as string;
      const img = new Image();
      img.onload = () => {
        const maxDim = 512;
        let width = img.width;
        let height = img.height;
        if (width > maxDim || height > maxDim) {
          const ratio = Math.min(maxDim / width, maxDim / height);
          width = Math.max(1, Math.round(width * ratio));
          height = Math.max(1, Math.round(height * ratio));
        }
        const canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext('2d');
        if (!ctx) {
          setWhitelabel(prev => ({ ...prev, logo_url: rawDataUrl }));
          return;
        }
        ctx.drawImage(img, 0, 0, width, height);
        const preferPng = file.type === 'image/png' || file.type === 'image/webp';
        let compressed = canvas.toDataURL(preferPng ? 'image/png' : 'image/jpeg', 0.86);
        if (compressed.length > 420000) {
          compressed = canvas.toDataURL('image/jpeg', 0.8);
        }
        if (compressed.length > 480000) {
          showToast('Ukuran logo terlalu besar setelah dikompresi. Gunakan gambar lebih kecil.');
          return;
        }
        setWhitelabel(prev => ({ ...prev, logo_url: compressed }));
      };
      img.onerror = () => {
        showToast('File gambar tidak dapat diproses.');
      };
      img.src = rawDataUrl;
    };
    reader.readAsDataURL(file);
    e.target.value = '';
  };

  // Whitelabel Save Handler
  const handleSaveWhitelabel = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSavingWhitelabel(true);
    try {
      const res = await apiFetch('/api/whitelabel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(whitelabel)
      });
      const data = await res.json();
      if (data.success) {
        const updatedWl = data.data || whitelabel;
        setWhitelabel(updatedWl);
        onWhitelabelUpdated?.(updatedWl);
        window.dispatchEvent(new CustomEvent('whitelabel-updated', { detail: updatedWl }));
        showToast('✓ Data Aplikasi, Nama, Footer & Nomor Gateway Utama Berhasil Disimpan & Diterapkan!');
        fetchData();
      }
    } catch (e) {
      showToast('Gagal menyimpan brand.');
    } finally {
      setIsSavingWhitelabel(false);
    }
  };

  // Meta AI Connection Test
  const handleTestMetaAiConnection = async () => {
    setIsTestingMetaAi(true);
    setMetaAiTestResult(null);
    try {
      const res = await apiFetch('/api/gemini/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      const data = await res.json();
      setMetaAiTestResult({
        success: Boolean(data.success),
        message: data.message || (data.success ? 'Sesi Meta AI WhatsApp siap!' : 'WhatsApp belum terhubung.')
      });
      fetchData(true);
    } catch (e: any) {
      setMetaAiTestResult({ success: false, message: e?.message || 'Gagal menguji koneksi Meta AI.' });
    } finally {
      setIsTestingMetaAi(false);
    }
  };

  // QRIS Image Upload Handler
  const handleQrImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      const base64 = reader.result as string;
      setQrisConfig(prev => ({ ...prev, image_url: base64 }));
    };
    reader.readAsDataURL(file);
  };

  const handleSaveQris = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSavingQris(true);
    try {
      const res = await apiFetch('/api/qris', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(qrisConfig)
      });
      const data = await res.json();
      if (data.success) {
        const updatedQris = data.data || qrisConfig;
        setQrisConfig(updatedQris);
        onQrisUpdated?.(updatedQris);
        window.dispatchEvent(new CustomEvent('qris-updated', { detail: updatedQris }));
        showToast('✓ Konfigurasi QRIS & Rekening Pembayaran Berhasil Disimpan!');
      }
    } catch (e) {
      showToast('Gagal menyimpan QRIS.');
    } finally {
      setIsSavingQris(false);
    }
  };

  // If Master PIN is not yet unlocked
  if (!isUnlocked) {
    return (
      <div className="max-w-md mx-auto my-12 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 sm:p-8 shadow-2xl text-center space-y-5">
        <div className="w-16 h-16 rounded-3xl bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 border border-indigo-200 dark:border-indigo-800 mx-auto flex items-center justify-center">
          <Lock className="w-8 h-8" />
        </div>

        <div className="space-y-1.5">
          <h3 className="text-lg font-black text-slate-900 dark:text-white">
            Superadmin Master Lock 🔒
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Akses pengaturan paket langganan, rotasi API key, dan whitelabel brand dilindungi dengan enkripsi PIN Master tingkat tinggi.
          </p>
        </div>

        {pinError && (
          <div className="p-3 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900 text-rose-700 dark:text-rose-300 rounded-xl text-xs font-bold flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{pinError}</span>
          </div>
        )}

        <form onSubmit={handleUnlockMaster} className="space-y-4">
          <div>
            <input
              type="password"
              required
              autoFocus
              value={pinInput}
              onChange={e => setPinInput(e.target.value)}
              placeholder="Masukkan PIN Master Superadmin"
              className="w-full text-center tracking-widest text-base font-black bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-2xl py-3 text-slate-900 dark:text-white focus:outline-none focus:border-indigo-500"
            />
          </div>

          <button
            type="submit"
            disabled={isVerifyingPin}
            className="w-full py-3 bg-indigo-600 hover:bg-indigo-500 text-white rounded-2xl text-xs font-black shadow-md transition-all flex items-center justify-center space-x-2 min-h-[44px]"
          >
            {isVerifyingPin ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Unlock className="w-4 h-4" />}
            <span>Buka Akses Master</span>
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 border border-indigo-500/30 rounded-3xl p-6 text-white shadow-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 bg-indigo-500/20 text-indigo-300 rounded-2xl border border-indigo-500/30 shrink-0">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-base sm:text-lg font-black text-indigo-200">
                Pusat Kontrol Superadmin Master
              </h2>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-black bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                TERVERIFIKASI
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-0.5">
              Atur seluruh ketentuan paket, status Meta AI WhatsApp, QRIS, dan identitas Whitelabel aplikasi.
            </p>
          </div>
        </div>

        <button
          onClick={async () => {
            await apiFetch('/api/auth/master-lock', { method: 'POST' }).catch(() => {});
            setIsUnlocked(false);
          }}
          className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-bold transition-all self-start sm:self-auto flex items-center space-x-1.5"
        >
          <Lock className="w-3.5 h-3.5" />
          <span>Kunci Kembali</span>
        </button>
      </div>

      {toastMsg && (
        <div className="p-3.5 bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/20 text-emerald-800 dark:text-emerald-300 rounded-2xl text-xs font-bold flex items-center space-x-2 animate-in fade-in">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
          <span>{toastMsg}</span>
        </div>
      )}

      {/* Tabs */}
      <div className="flex items-center space-x-2 border-b border-slate-200 dark:border-slate-800 pb-2 overflow-x-auto">
        <button
          onClick={() => setActiveTab('plans')}
          className={`px-4 py-2.5 rounded-xl text-xs font-black transition-all flex items-center space-x-2 ${
            activeTab === 'plans'
              ? 'bg-emerald-600 text-white shadow-xs'
              : 'bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-800'
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>Kelola Paket Langganan ({plans.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('whitelabel')}
          className={`px-4 py-2.5 rounded-xl text-xs font-black transition-all flex items-center space-x-2 ${
            activeTab === 'whitelabel'
              ? 'bg-emerald-600 text-white shadow-xs'
              : 'bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-800'
          }`}
        >
          <Globe className="w-4 h-4" />
          <span>Whitelabel &amp; No. Gateway Utama</span>
        </button>

        <button
          onClick={() => setActiveTab('smtp')}
          className={`px-4 py-2.5 rounded-xl text-xs font-black transition-all flex items-center space-x-2 ${
            activeTab === 'smtp'
              ? 'bg-emerald-600 text-white shadow-xs'
              : 'bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-800'
          }`}
        >
          <Mail className="w-4 h-4" />
          <span>Multi-SMTP Email ({smtpList.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('gemini')}
          className={`px-4 py-2.5 rounded-xl text-xs font-black transition-all flex items-center space-x-2 ${
            activeTab === 'gemini'
              ? 'bg-emerald-600 text-white shadow-xs'
              : 'bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-800'
          }`}
        >
          <Sparkles className="w-4 h-4" />
          <span>Meta AI WhatsApp ({metaAiSessions.length} Sesi)</span>
        </button>

        <button
          onClick={() => setActiveTab('qris')}
          className={`px-4 py-2.5 rounded-xl text-xs font-black transition-all flex items-center space-x-2 ${
            activeTab === 'qris'
              ? 'bg-emerald-600 text-white shadow-xs'
              : 'bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-800'
          }`}
        >
          <QrCode className="w-4 h-4" />
          <span>Upload QRIS &amp; Rekening</span>
        </button>
      </div>

      {/* TAB 1: PLANS MANAGEMENT */}
      {activeTab === 'plans' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center bg-white dark:bg-slate-900 p-5 rounded-3xl border border-slate-200 dark:border-slate-800">
            <div>
              <h4 className="text-sm font-black text-slate-900 dark:text-white">
                Daftar &amp; Ketentuan Paket Harga
              </h4>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Ubah harga, limit harian, atau fitur paket. Halaman depan dan form upgrade akan otomatis sinkron!
              </p>
            </div>

            <button
              onClick={() => {
                setEditingPlan({
                  id: `plan_${Date.now()}`,
                  name: 'Paket Kustom',
                  price: 150000,
                  period: '/ bulan',
                  max_sessions: 1,
                  daily_msg_limit: 5000,
                  monthly_msg_limit: 150000,
                  features: ['1 Nomor WhatsApp Terhubung', '5.000 Pesan / Hari', 'Tanpa Watermark'],
                  popular: false
                });
                setShowPlanModal(true);
              }}
              className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-black shadow-xs flex items-center space-x-1.5"
            >
              <Plus className="w-4 h-4" />
              <span>Tambah Paket</span>
            </button>
          </div>

          {/* Superadmin Global WhatsApp Capacity Limit Setting */}
          <form
            onSubmit={handleSaveMaxGlobalSessions}
            className="bg-white dark:bg-slate-900 p-5 rounded-3xl border border-slate-200 dark:border-slate-800 flex flex-col lg:flex-row lg:items-center justify-between gap-4"
          >
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-2xl bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 flex items-center justify-center shrink-0">
                <Smartphone className="w-5 h-5" />
              </div>
              <div className="space-y-1.5">
                <h5 className="text-sm font-black text-slate-900 dark:text-white">
                  Kapasitas Maksimal Nomor WhatsApp Global
                </h5>
                <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed max-w-2xl">
                  Semua paket dibatasi <strong>1 nomor WA per akun</strong>. Saat slot penuh, pendaftar Gratis baru ditahan, pendaftar Berbayar menggeser sesi Gratis dengan aktivitas pesan paling sedikit (prioritas 0 pesan), dan jika seluruh slot terisi Berbayar maka pendaftaran/upgrade baru ditahan sementara.
                </p>
                {slotStatus && (
                  <div className="flex flex-wrap items-center gap-2 pt-0.5 text-[11px] font-bold">
                    <span className="px-2.5 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200">
                      Terisi: {slotStatus.total_occupied} / {slotStatus.max_global_sessions}
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full bg-indigo-50 dark:bg-indigo-500/15 text-indigo-700 dark:text-indigo-300">
                      Berbayar (Kebal Geser): {slotStatus.paid_occupied}
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full bg-amber-50 dark:bg-amber-500/15 text-amber-700 dark:text-amber-300">
                      Gratis: {slotStatus.free_occupied}
                    </span>
                    <span
                      className={`px-2.5 py-0.5 rounded-full ${
                        slotStatus.available_slots === 0
                          ? 'bg-rose-100 dark:bg-rose-500/20 text-rose-700 dark:text-rose-300'
                          : 'bg-emerald-50 dark:bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                      }`}
                    >
                      Sisa Slot: {slotStatus.available_slots}
                    </span>
                  </div>
                )}
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <div className="flex items-center bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl px-3 py-1.5">
                <input
                  type="number"
                  step="1"
                  min={1}
                  max={10000}
                  value={maxGlobalSessions}
                  onChange={e => setMaxGlobalSessions(e.target.value)}
                  className="w-20 bg-transparent text-sm font-black font-mono text-slate-900 dark:text-white focus:outline-none text-right pr-1.5"
                  aria-label="Kapasitas maksimal nomor WhatsApp global"
                />
                <span className="text-xs font-bold text-slate-500 dark:text-slate-400">Nomor</span>
              </div>
              <button
                type="submit"
                disabled={isSavingMaxGlobal || !isUnlocked}
                className="px-4 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-black shadow-xs disabled:opacity-50"
              >
                {isSavingMaxGlobal ? 'Menyimpan...' : isUnlocked ? 'Simpan Kapasitas' : 'Buka PIN Dulu'}
              </button>
            </div>
          </form>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {plans.map(plan => (
              <div
                key={plan.id}
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-5 flex flex-col justify-between relative shadow-xs"
              >
                {plan.popular && (
                  <span className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 bg-emerald-600 text-white text-[10px] font-black rounded-full uppercase">
                    Paling Laris 🔥
                  </span>
                )}

                <div>
                  <div className="flex items-center justify-between">
                    <h5 className="font-black text-slate-900 dark:text-white text-sm">{plan.name}</h5>
                    <span className="text-[10px] font-mono text-slate-400 uppercase">ID: {plan.id}</span>
                  </div>

                  <div className="mt-3 flex items-baseline">
                    <span className="text-2xl font-black text-slate-900 dark:text-white">
                      Rp {plan.price.toLocaleString('id-ID')}
                    </span>
                    <span className="text-xs text-slate-500 ml-1">{plan.period}</span>
                  </div>

                  <div className="mt-3 p-2.5 bg-slate-50 dark:bg-slate-950 rounded-xl text-xs space-y-1">
                    <div className="font-bold text-emerald-600 flex items-center justify-between">
                      <span>⚡ Limit WA:</span>
                      <span>{plan.daily_msg_limit.toLocaleString('id-ID')} / hari</span>
                    </div>
                    <div className="font-bold text-indigo-600 dark:text-indigo-400 flex items-center justify-between">
                      <span>🤖 Respon AI:</span>
                      <span>{(plan.daily_ai_limit ?? 50).toLocaleString('id-ID')} / hari</span>
                    </div>
                    <div className="text-slate-500 text-[11px] flex items-center justify-between">
                      <span>📅 Limit AI / Bln:</span>
                      <span>{(plan.monthly_ai_limit ?? 1500).toLocaleString('id-ID')} / bln</span>
                    </div>
                    <div className="text-slate-500 text-[11px] flex items-center justify-between border-t border-slate-200/50 dark:border-slate-800 pt-1">
                      <span>📱 WhatsApp:</span>
                      <span>{plan.max_sessions} nomor</span>
                    </div>
                  </div>

                  <ul className="mt-4 space-y-1.5 text-xs text-slate-600 dark:text-slate-400">
                    {plan.features.slice(0, 4).map((f, i) => (
                      <li key={i} className="flex items-center space-x-1.5">
                        <Check className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                        <span className="truncate">{f}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="mt-5 pt-3 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between">
                  <button
                    onClick={() => {
                      setEditingPlan({ ...plan });
                      setShowPlanModal(true);
                    }}
                    className="px-3 py-1.5 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-xl text-xs font-bold flex items-center space-x-1"
                  >
                    <Edit2 className="w-3 h-3" />
                    <span>Edit Paket</span>
                  </button>

                  {plan.id !== 'free' && (
                    <button
                      onClick={() => {
                        setConfirmModal({
                          isOpen: true,
                          title: 'Hapus Paket?',
                          message: `Apakah Anda yakin ingin menghapus paket "${plan.name}"?`,
                          onConfirm: async () => {
                            await apiFetch(`/api/plans/${plan.id}`, { method: 'DELETE' });
                            fetchData();
                            setConfirmModal(prev => ({ ...prev, isOpen: false }));
                          }
                        });
                      }}
                      className="p-1.5 text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-950/40 rounded-xl"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 2: WHITELABEL & APP PRIMARY NUMBER */}
      {activeTab === 'whitelabel' && (
        <form onSubmit={handleSaveWhitelabel} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 shadow-xs space-y-5">
          <div>
            <h4 className="text-base font-black text-slate-900 dark:text-white">
              Informasi Brand Whitelabel, Footer &amp; Nomor WhatsApp Gateway Utama
            </h4>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Semua perubahan data aplikasi (Nama Aplikasi, Tagline, Perusahaan, Teks Footer, Logo, dan Nomor Gateway/CS) akan langsung diterapkan secara otomatis di halaman depan maupun di seluruh dalam aplikasi.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-black text-slate-700 dark:text-slate-300 block mb-1">
                Nama Aplikasi (Header, Judul &amp; Footer)
              </label>
              <input
                type="text"
                required
                value={whitelabel.app_name}
                onChange={e => setWhitelabel({ ...whitelabel, app_name: e.target.value })}
                placeholder="Contoh: Japriin"
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs font-bold text-slate-900 dark:text-white"
              />
            </div>

            <div>
              <label className="text-xs font-black text-slate-700 dark:text-slate-300 block mb-1">
                Nomor WhatsApp Gateway Utama Aplikasi (Kirim OTP &amp; Remote Bot)
              </label>
              <input
                type="text"
                required
                value={whitelabel.primary_bot_phone}
                onChange={e => setWhitelabel({ ...whitelabel, primary_bot_phone: e.target.value })}
                placeholder="081234567890"
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs font-mono font-bold text-emerald-600"
              />
            </div>

            <div>
              <label className="text-xs font-black text-slate-700 dark:text-slate-300 block mb-1">
                Nama Asisten Bot Pusat
              </label>
              <input
                type="text"
                required
                value={whitelabel.primary_bot_name}
                onChange={e => setWhitelabel({ ...whitelabel, primary_bot_name: e.target.value })}
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs text-slate-900 dark:text-white"
              />
            </div>

            <div>
              <label className="text-xs font-black text-slate-700 dark:text-slate-300 block mb-1">
                Nama Perusahaan / Organisasi Resmi
              </label>
              <input
                type="text"
                value={whitelabel.company_name}
                onChange={e => setWhitelabel({ ...whitelabel, company_name: e.target.value })}
                placeholder="Contoh: PT Teknologi Indonesia"
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs text-slate-900 dark:text-white"
              />
            </div>

            <div>
              <label className="text-xs font-black text-slate-700 dark:text-slate-300 block mb-1">
                Nomor WhatsApp Customer Service / Bantuan (Footer &amp; Konfirmasi)
              </label>
              <input
                type="text"
                value={whitelabel.support_phone || ''}
                onChange={e => setWhitelabel({ ...whitelabel, support_phone: e.target.value })}
                placeholder="081234567890"
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs font-mono text-slate-900 dark:text-white"
              />
            </div>

            <div>
              <label className="text-xs font-black text-slate-700 dark:text-slate-300 block mb-1">
                Logo Aplikasi (URL Gambar atau Upload File)
              </label>
              <div className="flex items-center gap-2">
                <img
                  src={resolveLogoUrl(whitelabel.logo_url)}
                  alt="Logo Preview"
                  onError={handleLogoImgError}
                  className="w-9 h-9 rounded-xl object-cover border border-slate-200 dark:border-slate-700 shrink-0"
                />
                <input
                  type="text"
                  value={whitelabel.logo_url}
                  onChange={e => setWhitelabel({ ...whitelabel, logo_url: e.target.value })}
                  placeholder={DEFAULT_PUBLIC_LOGO_URL}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs text-slate-900 dark:text-white"
                />
                <label className="px-3 py-2.5 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-xl text-xs font-bold cursor-pointer shrink-0 flex items-center space-x-1 border border-slate-200 dark:border-slate-700">
                  <Upload className="w-3.5 h-3.5" />
                  <span>Upload</span>
                  <input type="file" accept="image/*" onChange={handleLogoImageUpload} className="hidden" />
                </label>
              </div>
            </div>

            <div className="md:col-span-2">
              <label className="text-xs font-black text-slate-700 dark:text-slate-300 block mb-1">
                Tagline Aplikasi (Sub-judul Header &amp; Deskripsi Brand)
              </label>
              <input
                type="text"
                value={whitelabel.tagline}
                onChange={e => setWhitelabel({ ...whitelabel, tagline: e.target.value })}
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs text-slate-900 dark:text-white"
              />
            </div>

            <div className="md:col-span-2">
              <label className="text-xs font-black text-slate-700 dark:text-slate-300 block mb-1">
                Teks Footer Copyright (Ditampilkan di Bagian Bawah Dashboard &amp; Halaman Depan)
              </label>
              <input
                type="text"
                value={whitelabel.footer_text}
                onChange={e => setWhitelabel({ ...whitelabel, footer_text: e.target.value })}
                placeholder="Dikelola secara profesional oleh perusahaan Anda"
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs text-slate-900 dark:text-white"
              />
            </div>
          </div>

          {/* Live Preview of Header & Footer */}
          <div className="p-4 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-2xl space-y-3">
            <span className="text-[11px] font-black uppercase tracking-wider text-emerald-600 dark:text-emerald-400 block">
              Pratinjau Langsung (Live Preview Header &amp; Footer Aplikasi):
            </span>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 bg-white dark:bg-slate-900 rounded-xl border border-slate-200/80 dark:border-slate-800">
              <div className="flex items-center space-x-2.5">
                <img
                  src={resolveLogoUrl(whitelabel.logo_url)}
                  alt={whitelabel.app_name}
                  onError={handleLogoImgError}
                  className="w-8 h-8 rounded-lg object-cover"
                />
                <div>
                  <div className="text-xs font-black text-slate-900 dark:text-white">{whitelabel.app_name || 'Nama Aplikasi'}</div>
                  <div className="text-[10px] text-slate-400">{whitelabel.tagline || 'Tagline Aplikasi'}</div>
                </div>
              </div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400 border-t sm:border-t-0 pt-2 sm:pt-0 border-slate-100 dark:border-slate-800">
                <strong className="text-slate-800 dark:text-slate-200">{whitelabel.app_name}</strong>
                {whitelabel.company_name ? ` (${whitelabel.company_name})` : ''} • {whitelabel.footer_text}
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-slate-100 dark:border-slate-800 flex justify-end">
            <button
              type="submit"
              disabled={isSavingWhitelabel}
              className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-black shadow-md flex items-center space-x-2"
            >
              {isSavingWhitelabel && <RefreshCw className="w-4 h-4 animate-spin" />}
              <span>Simpan &amp; Terapkan Konfigurasi Brand</span>
            </button>
          </div>
        </form>
      )}

      {/* TAB: MULTI-SMTP EMAIL ROTATION */}
      {activeTab === 'smtp' && (
        <div className="space-y-6">
          {smtpErrorMsg && (
            <div className="p-3.5 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-700 dark:text-rose-300 rounded-2xl text-xs font-bold flex items-center justify-between gap-2">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{smtpErrorMsg}</span>
              </div>
              <button type="button" onClick={() => setSmtpErrorMsg('')} className="opacity-60 hover:opacity-100">
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 shadow-xs space-y-4">
            <div>
              <h4 className="text-sm font-black text-slate-900 dark:text-white flex items-center space-x-2">
                <Mail className="w-4 h-4 text-emerald-500" />
                <span>Tambah Akun SMTP Email untuk Rotasi &amp; OTP</span>
              </h4>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                Mendukung SMTP Gmail (16 digit App Password) maupun SMTP domain cPanel/VPS. Jika akun pertama gagal, sistem otomatis melakukan failover ke akun berikutnya.
              </p>
            </div>

            <form
              onSubmit={async e => {
                e.preventDefault();
                if (!newSmtpUser.trim() || !newSmtpPass.trim()) {
                  setSmtpErrorMsg('Email pengirim dan App Password wajib diisi.');
                  return;
                }
                setIsAddingSmtp(true);
                setSmtpErrorMsg('');
                try {
                  const portNum = Number(newSmtpPort) || 587;
                  const res = await apiFetch('/api/smtp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                      name: newSmtpName.trim() || `SMTP (${newSmtpUser.trim().split('@')[0]})`,
                      host: newSmtpHost.trim() || 'smtp.gmail.com',
                      port: portNum,
                      secure: portNum === 465 ? true : portNum === 587 ? false : newSmtpSecure,
                      user: newSmtpUser.trim(),
                      pass: newSmtpPass.trim(),
                      sender_name: newSmtpSenderName.trim() || whitelabel.app_name || 'Japriin',
                      is_active: true
                    })
                  });
                  const data = await res.json();
                  if (res.ok && data.success) {
                    showToast('✓ Akun SMTP berhasil ditambahkan ke rotasi!');
                    setNewSmtpName('');
                    setNewSmtpUser('');
                    setNewSmtpPass('');
                    setNewSmtpSenderName('');
                    if (data.data) {
                      setSmtpList(prev => [...prev, data.data]);
                    }
                    fetchData(true);
                  } else if (data?.code === 'MASTER_PIN_REQUIRED') {
                    setIsUnlocked(false);
                    setPinError(data.error || 'Sesi PIN Master berakhir. Masukkan PIN Master kembali.');
                  } else {
                    setSmtpErrorMsg(data.error || 'Gagal menambahkan akun SMTP.');
                  }
                } catch (err: any) {
                  setSmtpErrorMsg(err?.message || 'Gagal menghubungi server saat menambahkan SMTP.');
                } finally {
                  setIsAddingSmtp(false);
                }
              }}
              className="space-y-3"
            >
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                <div>
                  <label className="text-[11px] font-bold text-slate-600 dark:text-slate-400 block mb-1">Label / Nama Akun</label>
                  <input
                    type="text"
                    value={newSmtpName}
                    onChange={e => setNewSmtpName(e.target.value)}
                    placeholder="Contoh: Gmail Utama"
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-600 dark:text-slate-400 block mb-1">Host SMTP</label>
                  <input
                    type="text"
                    required
                    value={newSmtpHost}
                    onChange={e => setNewSmtpHost(e.target.value)}
                    placeholder="smtp.gmail.com"
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs font-mono"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-600 dark:text-slate-400 block mb-1">Port SMTP</label>
                  <select
                    value={newSmtpPort}
                    onChange={e => {
                      const p = Number(e.target.value);
                      setNewSmtpPort(p);
                      setNewSmtpSecure(p === 465);
                    }}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs font-bold"
                  >
                    <option value={587}>587 (TLS / STARTTLS)</option>
                    <option value={465}>465 (SSL Secure)</option>
                    <option value={25}>25 (Non-SSL)</option>
                    <option value={2525}>2525 (Alt TLS)</option>
                  </select>
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-600 dark:text-slate-400 block mb-1">Email Pengirim (User)</label>
                  <input
                    type="email"
                    required
                    value={newSmtpUser}
                    onChange={e => setNewSmtpUser(e.target.value)}
                    placeholder="emailanda@gmail.com"
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-600 dark:text-slate-400 block mb-1">Nama Pengirim (Sender Name)</label>
                  <input
                    type="text"
                    value={newSmtpSenderName}
                    onChange={e => setNewSmtpSenderName(e.target.value)}
                    placeholder={whitelabel.app_name || 'Japriin'}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-600 dark:text-slate-400 block mb-1">App Password / Password</label>
                  <input
                    type="password"
                    required
                    value={newSmtpPass}
                    onChange={e => setNewSmtpPass(e.target.value)}
                    placeholder="xxxx xxxx xxxx xxxx"
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs"
                  />
                </div>
              </div>
              <div className="flex justify-end pt-1">
                <button
                  type="submit"
                  disabled={isAddingSmtp}
                  className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-black shadow-xs flex items-center space-x-1.5 disabled:opacity-50"
                >
                  {isAddingSmtp ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                  <span>{isAddingSmtp ? 'Menambahkan...' : 'Tambahkan ke Rotasi'}</span>
                </button>
              </div>
            </form>
          </div>

          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 shadow-xs space-y-4">
            <h5 className="text-xs font-black uppercase tracking-wider text-slate-700 dark:text-slate-300">
              Daftar Akun SMTP Terdaftar ({smtpList.length})
            </h5>

            {smtpList.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-400">
                Belum ada akun SMTP. Tambahkan di atas untuk mengaktifkan pengiriman OTP Email.
              </div>
            ) : (
              <div className="divide-y divide-slate-100 dark:divide-slate-800">
                {smtpList.map(acc => (
                  <div key={acc.id} className="py-3 space-y-2.5">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-black text-xs text-slate-900 dark:text-white">{acc.name}</span>
                          <span className="text-[11px] font-mono text-slate-500">({acc.user})</span>
                          <span className="text-[10px] font-mono px-2 py-0.5 bg-slate-100 dark:bg-slate-800 rounded text-slate-600 dark:text-slate-300">
                            {acc.host}:{acc.port}
                          </span>
                          {acc.needs_password_reset && (
                            <button
                              type="button"
                              onClick={() => {
                                setEditingSmtp({
                                  id: acc.id,
                                  name: acc.name || '',
                                  host: acc.host || 'smtp.gmail.com',
                                  port: Number(acc.port) || 587,
                                  secure: Boolean(acc.secure),
                                  user: acc.user || '',
                                  sender_name: acc.sender_name || '',
                                  pass: '',
                                  is_active: acc.is_active !== false
                                });
                                setSmtpErrorMsg('');
                              }}
                              className="text-[10px] font-bold px-2 py-0.5 bg-amber-50 dark:bg-amber-500/10 hover:bg-amber-100 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-500/30 rounded"
                            >
                              ⚠️ App Password Perlu Diperbarui (Klik untuk Edit)
                            </button>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-400 mt-0.5 space-x-2">
                          <span className="text-emerald-600 font-bold">✓ {acc.success_count || 0} Sukses</span>
                          <span>•</span>
                          <span className={acc.error_count ? 'text-rose-500 font-bold' : ''}>✗ {acc.error_count || 0} Gagal</span>
                          {acc.sender_name && <span>• Pengirim: {acc.sender_name}</span>}
                          {acc.last_error && <span className="text-rose-500">• {acc.last_error}</span>}
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          type="button"
                          onClick={() => {
                            if (editingSmtp?.id === acc.id) {
                              setEditingSmtp(null);
                            } else {
                              setEditingSmtp({
                                id: acc.id,
                                name: acc.name || '',
                                host: acc.host || 'smtp.gmail.com',
                                port: Number(acc.port) || 587,
                                secure: Boolean(acc.secure),
                                user: acc.user || '',
                                sender_name: acc.sender_name || '',
                                pass: '',
                                is_active: acc.is_active !== false
                              });
                              setSmtpErrorMsg('');
                            }
                          }}
                          className="px-3 py-1.5 bg-amber-50 dark:bg-amber-950/50 hover:bg-amber-100 text-amber-700 dark:text-amber-300 rounded-xl text-xs font-bold flex items-center space-x-1"
                        >
                          <Edit2 className="w-3.5 h-3.5" />
                          <span>Edit</span>
                        </button>

                        <button
                          type="button"
                          onClick={async () => {
                            setTestingSmtpId(acc.id);
                            setSmtpErrorMsg('');
                            try {
                              const r = await apiFetch('/api/smtp/test', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ account_id: acc.id, recipient_email: testEmailRecipient.trim() || undefined })
                              }).then(res => res.json());
                              if (r.success) showToast(`✓ ${r.message}`);
                              else setSmtpErrorMsg(r.error || r.message || 'Tes koneksi SMTP gagal.');
                              fetchData(true);
                            } catch (e: any) {
                              setSmtpErrorMsg(e?.message || 'Gagal menguji koneksi SMTP.');
                            } finally {
                              setTestingSmtpId(null);
                            }
                          }}
                          disabled={testingSmtpId === acc.id}
                          className="px-3 py-1.5 bg-indigo-50 dark:bg-indigo-950/50 hover:bg-indigo-100 text-indigo-600 dark:text-indigo-300 rounded-xl text-xs font-bold flex items-center space-x-1"
                        >
                          {testingSmtpId === acc.id ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                          <span>Tes Koneksi</span>
                        </button>

                        <button
                          type="button"
                          onClick={async () => {
                            setSmtpErrorMsg('');
                            try {
                              const res = await apiFetch(`/api/smtp/${acc.id}/toggle`, { method: 'PUT' });
                              const data = await res.json();
                              if (res.ok && data.success) {
                                if (data.data) {
                                  setSmtpList(prev => prev.map(s => (s.id === acc.id ? data.data : s)));
                                }
                                showToast(`✓ ${data.message || 'Status akun SMTP diperbarui.'}`);
                                fetchData(true);
                              } else if (data?.code === 'MASTER_PIN_REQUIRED') {
                                setIsUnlocked(false);
                                setPinError(data.error || 'Sesi PIN Master berakhir. Masukkan PIN Master kembali.');
                              } else {
                                setSmtpErrorMsg(data.error || 'Gagal mengubah status akun SMTP.');
                              }
                            } catch (e: any) {
                              setSmtpErrorMsg(e?.message || 'Gagal menghubungi server.');
                            }
                          }}
                          className={`px-3 py-1.5 rounded-xl text-xs font-bold ${
                            acc.is_active !== false
                              ? 'bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-300'
                              : 'bg-slate-100 dark:bg-slate-800 text-slate-500'
                          }`}
                        >
                          {acc.is_active !== false ? 'Aktif' : 'Non-Aktif'}
                        </button>

                        <button
                          type="button"
                          onClick={() => {
                            setConfirmModal({
                              isOpen: true,
                              title: 'Hapus Akun SMTP?',
                              message: `Anda yakin ingin menghapus akun SMTP "${acc.name}" (${acc.user}) dari sistem rotasi email?`,
                              onConfirm: async () => {
                                setConfirmModal(prev => ({ ...prev, isOpen: false }));
                                setSmtpErrorMsg('');
                                try {
                                  const res = await apiFetch(`/api/smtp/${acc.id}`, { method: 'DELETE' });
                                  const data = await res.json();
                                  if (res.ok && data.success) {
                                    if (editingSmtp?.id === acc.id) setEditingSmtp(null);
                                    setSmtpList(prev => prev.filter(s => s.id !== acc.id));
                                    showToast('✓ Akun SMTP berhasil dihapus.');
                                    fetchData(true);
                                  } else if (data?.code === 'MASTER_PIN_REQUIRED') {
                                    setIsUnlocked(false);
                                    setPinError(data.error || 'Sesi PIN Master berakhir. Masukkan PIN Master kembali.');
                                  } else {
                                    setSmtpErrorMsg(data.error || 'Gagal menghapus akun SMTP.');
                                  }
                                } catch (e: any) {
                                  setSmtpErrorMsg(e?.message || 'Gagal menghubungi server saat menghapus akun SMTP.');
                                }
                              }
                            });
                          }}
                          className="p-1.5 text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-950/40 rounded-xl"
                          title="Hapus Akun SMTP"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>

                    {editingSmtp && editingSmtp.id === acc.id && (
                      <form
                        onSubmit={async e => {
                          e.preventDefault();
                          if (!editingSmtp.name.trim() || !editingSmtp.host.trim() || !editingSmtp.user.trim()) {
                            setSmtpErrorMsg('Nama akun, Host SMTP, dan Email pengirim wajib diisi.');
                            return;
                          }
                          setIsSavingEditSmtp(true);
                          setSmtpErrorMsg('');
                          try {
                            const portNum = Number(editingSmtp.port) || 587;
                            const payload: Record<string, any> = {
                              name: editingSmtp.name.trim(),
                              host: editingSmtp.host.trim(),
                              port: portNum,
                              secure: portNum === 465 ? true : portNum === 587 ? false : editingSmtp.secure,
                              user: editingSmtp.user.trim(),
                              sender_name: editingSmtp.sender_name.trim() || whitelabel.app_name || 'Japriin',
                              is_active: editingSmtp.is_active
                            };
                            if (editingSmtp.pass.trim()) {
                              payload.pass = editingSmtp.pass.trim();
                            }

                            const res = await apiFetch(`/api/smtp/${acc.id}`, {
                              method: 'PUT',
                              headers: { 'Content-Type': 'application/json' },
                              body: JSON.stringify(payload)
                            });
                            const r = await res.json();
                            if (res.ok && r.success) {
                              showToast(`✓ Konfigurasi SMTP ${editingSmtp.user} berhasil diperbarui!`);
                              setEditingSmtp(null);
                              if (r.data) {
                                setSmtpList(prev => prev.map(s => (s.id === acc.id ? r.data : s)));
                              }
                              fetchData(true);
                            } else if (r?.code === 'MASTER_PIN_REQUIRED') {
                              setIsUnlocked(false);
                              setPinError(r.error || 'Sesi PIN Master berakhir. Masukkan PIN Master kembali.');
                            } else {
                              setSmtpErrorMsg(r.error || 'Gagal memperbarui akun SMTP.');
                            }
                          } catch (err: any) {
                            setSmtpErrorMsg(err?.message || 'Gagal menghubungi server.');
                          } finally {
                            setIsSavingEditSmtp(false);
                          }
                        }}
                        className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-2xl p-4 space-y-3"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-black text-slate-800 dark:text-white flex items-center space-x-1.5">
                            <Edit2 className="w-3.5 h-3.5 text-amber-600" />
                            <span>Edit Konfigurasi Akun SMTP</span>
                          </span>
                          <label className="flex items-center space-x-1.5 text-[11px] font-bold text-slate-700 dark:text-slate-300 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={editingSmtp.is_active}
                              onChange={e => setEditingSmtp(prev => (prev ? { ...prev, is_active: e.target.checked } : null))}
                              className="rounded text-emerald-600"
                            />
                            <span>Aktif dalam Rotasi</span>
                          </label>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
                          <div>
                            <label className="text-[10px] font-bold text-slate-600 dark:text-slate-400 block mb-1">Label / Nama Akun</label>
                            <input
                              type="text"
                              required
                              value={editingSmtp.name}
                              onChange={e => setEditingSmtp(prev => (prev ? { ...prev, name: e.target.value } : null))}
                              className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs"
                            />
                          </div>
                          <div>
                            <label className="text-[10px] font-bold text-slate-600 dark:text-slate-400 block mb-1">Host SMTP</label>
                            <input
                              type="text"
                              required
                              value={editingSmtp.host}
                              onChange={e => setEditingSmtp(prev => (prev ? { ...prev, host: e.target.value } : null))}
                              className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono"
                            />
                          </div>
                          <div>
                            <label className="text-[10px] font-bold text-slate-600 dark:text-slate-400 block mb-1">Port SMTP</label>
                            <select
                              value={editingSmtp.port}
                              onChange={e => {
                                const p = Number(e.target.value);
                                setEditingSmtp(prev => (prev ? { ...prev, port: p, secure: p === 465 } : null));
                              }}
                              className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs font-bold"
                            >
                              <option value={587}>587 (TLS / STARTTLS)</option>
                              <option value={465}>465 (SSL Secure)</option>
                              <option value={25}>25 (Non-SSL)</option>
                              <option value={2525}>2525 (Alt TLS)</option>
                            </select>
                          </div>
                          <div>
                            <label className="text-[10px] font-bold text-slate-600 dark:text-slate-400 block mb-1">Email Pengirim (User)</label>
                            <input
                              type="email"
                              required
                              value={editingSmtp.user}
                              onChange={e => setEditingSmtp(prev => (prev ? { ...prev, user: e.target.value } : null))}
                              className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs"
                            />
                          </div>
                          <div>
                            <label className="text-[10px] font-bold text-slate-600 dark:text-slate-400 block mb-1">Nama Pengirim (Sender Name)</label>
                            <input
                              type="text"
                              value={editingSmtp.sender_name}
                              onChange={e => setEditingSmtp(prev => (prev ? { ...prev, sender_name: e.target.value } : null))}
                              placeholder={whitelabel.app_name || 'Japriin'}
                              className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs"
                            />
                          </div>
                          <div>
                            <label className="text-[10px] font-bold text-slate-600 dark:text-slate-400 block mb-1">
                              App Password Baru <span className="font-normal text-slate-400">(opsional)</span>
                            </label>
                            <input
                              type="password"
                              value={editingSmtp.pass}
                              onChange={e => setEditingSmtp(prev => (prev ? { ...prev, pass: e.target.value } : null))}
                              placeholder={acc.pass_masked ? `Tersimpan (${acc.pass_masked}) - kosongkan jika tetap` : 'Masukkan App Password baru'}
                              className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs"
                            />
                          </div>
                        </div>

                        <div className="flex items-center justify-end space-x-2 pt-1">
                          <button
                            type="button"
                            onClick={() => setEditingSmtp(null)}
                            className="px-3 py-1.5 bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 rounded-lg text-xs font-bold"
                          >
                            Batal
                          </button>
                          <button
                            type="submit"
                            disabled={isSavingEditSmtp}
                            className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-black disabled:opacity-50"
                          >
                            {isSavingEditSmtp ? 'Menyimpan...' : 'Simpan Perubahan'}
                          </button>
                        </div>
                      </form>
                    )}
                  </div>
                ))}
              </div>
            )}

            <div className="pt-4 border-t border-slate-100 dark:border-slate-800 flex flex-col sm:flex-row items-center gap-3">
              <input
                type="email"
                value={testEmailRecipient}
                onChange={e => setTestEmailRecipient(e.target.value)}
                placeholder="Masukkan email tujuan untuk tes kirim (contoh: tujuan@gmail.com)"
                className="w-full sm:flex-1 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs"
              />
              <button
                type="button"
                disabled={isSendingTestEmail || !testEmailRecipient.trim()}
                onClick={async () => {
                  setIsSendingTestEmail(true);
                  setSmtpErrorMsg('');
                  try {
                    const r = await apiFetch('/api/smtp/test', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ recipient_email: testEmailRecipient.trim() })
                    }).then(res => res.json());
                    if (r.success) showToast(`✓ ${r.message}`);
                    else setSmtpErrorMsg(r.error || r.message || 'Gagal mengirim email uji coba.');
                    fetchData();
                  } catch (e: any) {
                    setSmtpErrorMsg(e?.message || 'Gagal mengirim email uji coba.');
                  } finally {
                    setIsSendingTestEmail(false);
                  }
                }}
                className="w-full sm:w-auto px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-black flex items-center justify-center space-x-1.5 disabled:opacity-50"
              >
                <Send className="w-3.5 h-3.5" />
                <span>{isSendingTestEmail ? 'Mengirim...' : 'Kirim Email Uji Coba'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: META AI WHATSAPP (BAILEYS) */}
      {activeTab === 'gemini' && (
        <div className="space-y-6">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 shadow-xs space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h4 className="text-sm font-black text-slate-900 dark:text-white flex items-center space-x-2">
                  <Sparkles className="w-4 h-4 text-emerald-500" />
                  <span>Arsitektur Meta AI WhatsApp (Tanpa API Key Eksternal)</span>
                </h4>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                  Aplikasi tidak lagi memakai Gemini API Key. Setiap pesan pelanggan yang masuk dikirim langsung ke chat <strong>Meta AI</strong> (<code className="font-mono">{metaAiJid}</code>) di sesi WhatsApp Baileys masing-masing tenant lalu balasannya diteruskan kembali ke pelanggan.
                </p>
              </div>
              <button
                type="button"
                onClick={handleTestMetaAiConnection}
                disabled={isTestingMetaAi}
                className="px-4 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-black shadow-xs flex items-center space-x-1.5 shrink-0"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isTestingMetaAi ? 'animate-spin' : ''}`} />
                <span>Cek Status Meta AI</span>
              </button>
            </div>

            {metaAiTestResult && (
              <div className={`p-3 rounded-2xl text-xs font-bold border ${
                metaAiTestResult.success
                  ? 'bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-800 text-emerald-700 dark:text-emerald-300'
                  : 'bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-300'
              }`}>
                {metaAiTestResult.message}
              </div>
            )}
          </div>

          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl overflow-hidden shadow-xs">
            <div className="p-4 bg-slate-50 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800">
              <h5 className="text-xs font-black uppercase tracking-wider text-slate-700 dark:text-slate-300">
                Sesi WhatsApp Baileys Siap Meta AI ({metaAiSessions.length})
              </h5>
            </div>

            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {metaAiSessions.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-400">
                  Belum ada sesi WhatsApp Baileys yang terhubung saat ini. Hubungkan nomor WhatsApp melalui menu Koneksi.
                </div>
              ) : (
                metaAiSessions.map(s => (
                  <div key={s.sessionId} className="p-4 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-black text-slate-900 dark:text-white text-xs font-mono">{s.phoneNumber || s.sessionId}</span>
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300">
                          Terhubung · Meta AI Siap
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5 space-x-2 font-mono">
                        <span>Session: {s.sessionId}</span>
                        <span>•</span>
                        <span>User ID: {s.userId}</span>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl overflow-hidden shadow-xs">
            <div className="p-4 bg-slate-50 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h5 className="text-xs font-black uppercase tracking-wider text-slate-700 dark:text-slate-300">
                  Log Audit Error &amp; Aktivitas AI Server
                </h5>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                  Tersimpan persisten di file server <code className="font-mono font-bold text-slate-700 dark:text-slate-200">{aiAuditLogFile}</code> (rotasi otomatis 2 MB, nomor tersensor).
                </p>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                {(['ALL', 'ERROR', 'WARN', 'INFO'] as const).map(lvl => (
                  <button
                    key={lvl}
                    type="button"
                    onClick={() => handleRefreshAiAuditLogs(lvl)}
                    className={`px-2.5 py-1.5 rounded-lg text-[10px] font-black transition-colors ${
                      aiAuditLevelFilter === lvl
                        ? 'bg-slate-900 dark:bg-emerald-600 text-white'
                        : 'bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-800'
                    }`}
                  >
                    {lvl === 'ALL' ? 'Semua' : lvl}
                  </button>
                ))}
                <button
                  type="button"
                  onClick={() => handleRefreshAiAuditLogs(aiAuditLevelFilter)}
                  disabled={isLoadingAuditLogs}
                  className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-[11px] font-bold flex items-center gap-1 disabled:opacity-50"
                >
                  <RefreshCw className={`w-3 h-3 ${isLoadingAuditLogs ? 'animate-spin' : ''}`} />
                  <span>Segarkan</span>
                </button>
              </div>
            </div>

            <div className="divide-y divide-slate-100 dark:divide-slate-800 max-h-96 overflow-y-auto">
              {aiAuditLogs.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-400">
                  Belum ada catatan log audit AI pada filter ini. Setiap error Meta AI, timeout, ACK ditolak, kuota habis, atau sukses balasan akan tercatat otomatis di sini dan di <code className="font-mono">{aiAuditLogFile}</code>.
                </div>
              ) : (
                aiAuditLogs.map((entry, idx) => (
                  <div key={`${entry.timestamp}-${idx}`} className="p-3.5 text-xs space-y-1">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-black ${
                          entry.level === 'ERROR'
                            ? 'bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300'
                            : entry.level === 'WARN'
                              ? 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300'
                              : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300'
                        }`}>
                          {entry.level}
                        </span>
                        <span className="font-mono text-[11px] font-bold text-slate-700 dark:text-slate-200">{entry.stage}</span>
                        {entry.error_code && (
                          <code className="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-[10px] font-mono text-rose-700 dark:text-rose-300">
                            {entry.error_code}
                          </code>
                        )}
                        {entry.latency_ms !== undefined && (
                          <span className="text-[10px] font-mono text-slate-400">{entry.latency_ms}ms</span>
                        )}
                      </div>
                      <span className="text-[10px] font-mono text-slate-400">
                        {new Date(entry.timestamp).toLocaleString('id-ID')}
                      </span>
                    </div>
                    <p className="text-slate-700 dark:text-slate-300 text-[11px] leading-relaxed">{entry.reason}</p>
                    <div className="text-[10px] font-mono text-slate-400 flex flex-wrap gap-x-3 gap-y-0.5">
                      {entry.session_id && <span>session: {entry.session_id}</span>}
                      {entry.user_id && <span>user: {entry.user_id}</span>}
                      {entry.customer_code && <span>chat: {entry.customer_code}</span>}
                      {entry.sender_masked && <span>sender: {entry.sender_masked}</span>}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: UPLOAD QRIS & REKENING */}
      {activeTab === 'qris' && (
        <form onSubmit={handleSaveQris} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 shadow-xs space-y-5">
          <div>
            <h4 className="text-base font-black text-slate-900 dark:text-white">
              Pengaturan QRIS &amp; Rekening Pembayaran Resmi
            </h4>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Upload foto barcode QRIS langsung dari perangkat Anda atau masukkan URL gambar. Barcode ini akan muncul saat pembeli melakukan checkout paket.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-start">
            <div className="space-y-4">
              <div>
                <label className="text-xs font-black text-slate-700 dark:text-slate-300 block mb-1">
                  Upload File Barcode QRIS
                </label>
                <input
                  type="file"
                  accept="image/*"
                  onChange={handleQrImageUpload}
                  className="w-full text-xs text-slate-500 file:mr-3 file:py-2 file:px-4 file:rounded-xl file:border-0 file:text-xs file:font-black file:bg-emerald-50 file:text-emerald-700 hover:file:bg-emerald-100"
                />
              </div>

              <div>
                <label className="text-xs font-black text-slate-700 dark:text-slate-300 block mb-1">
                  Atau Masukkan URL Barcode QRIS
                </label>
                <input
                  type="url"
                  value={qrisConfig.image_url}
                  onChange={e => setQrisConfig({ ...qrisConfig, image_url: e.target.value })}
                  placeholder="https://..."
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-black text-slate-700 dark:text-slate-300 block mb-1">
                    Nama Bank / E-Wallet
                  </label>
                  <input
                    type="text"
                    required
                    value={qrisConfig.bank_name}
                    onChange={e => setQrisConfig({ ...qrisConfig, bank_name: e.target.value })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs"
                  />
                </div>

                <div>
                  <label className="text-xs font-black text-slate-700 dark:text-slate-300 block mb-1">
                    Nomor Rekening / HP
                  </label>
                  <input
                    type="text"
                    required
                    value={qrisConfig.account_number}
                    onChange={e => setQrisConfig({ ...qrisConfig, account_number: e.target.value })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs font-mono font-bold"
                  />
                </div>
              </div>

              <div>
                <label className="text-xs font-black text-slate-700 dark:text-slate-300 block mb-1">
                  Atas Nama Pemilik Rekening (NMID)
                </label>
                <input
                  type="text"
                  required
                  value={qrisConfig.account_name}
                  onChange={e => setQrisConfig({ ...qrisConfig, account_name: e.target.value })}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs font-bold"
                />
              </div>
            </div>

            {/* QR Preview */}
            <div className="bg-slate-50 dark:bg-slate-950 p-6 rounded-3xl border border-slate-200 dark:border-slate-800 text-center space-y-3">
              <span className="text-xs font-black text-slate-700 dark:text-slate-300 block">
                Pratinjau QRIS di Layar Pembeli:
              </span>
              <div className="w-48 h-48 mx-auto bg-white p-2 rounded-2xl shadow-md border border-slate-200 flex items-center justify-center">
                <img
                  src={qrisConfig.image_url || 'https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=JAPRIIN'}
                  alt="QRIS Preview"
                  className="w-full h-full object-contain"
                />
              </div>
              <h5 className="font-black text-xs text-slate-900 dark:text-white">{qrisConfig.account_name}</h5>
            </div>
          </div>

          <div className="pt-4 border-t border-slate-100 dark:border-slate-800 flex justify-end">
            <button
              type="submit"
              disabled={isSavingQris}
              className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-black shadow-md flex items-center space-x-2"
            >
              {isSavingQris && <RefreshCw className="w-4 h-4 animate-spin" />}
              <span>Simpan QRIS &amp; Rekening</span>
            </button>
          </div>
        </form>
      )}

      {/* PLAN EDIT MODAL */}
      {showPlanModal && editingPlan && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-xs z-[100] flex items-center justify-center p-4 overflow-y-auto animate-in fade-in">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl w-full max-w-lg p-6 space-y-4 shadow-2xl relative">
            <button
              onClick={() => {
                setShowPlanModal(false);
                setEditingPlan(null);
              }}
              className="absolute top-4 right-4 p-2 text-slate-400 hover:text-slate-600 rounded-full hover:bg-slate-100 dark:hover:bg-slate-800"
            >
              <X className="w-5 h-5" />
            </button>

            <h3 className="text-base font-black text-slate-900 dark:text-white flex items-center space-x-2 border-b border-slate-100 dark:border-slate-800 pb-3">
              <Layers className="w-5 h-5 text-emerald-600" />
              <span>Edit Ketentuan Paket</span>
            </h3>

            <form onSubmit={handleSavePlan} className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-bold text-slate-700 dark:text-slate-300 block mb-1">ID Paket</label>
                  <input
                    type="text"
                    required
                    disabled={editingPlan.id === 'free'}
                    value={editingPlan.id}
                    onChange={e => setEditingPlan({ ...editingPlan, id: e.target.value })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs font-mono disabled:opacity-50"
                  />
                </div>

                <div>
                  <label className="text-xs font-bold text-slate-700 dark:text-slate-300 block mb-1">Nama Paket</label>
                  <input
                    type="text"
                    required
                    value={editingPlan.name}
                    onChange={e => setEditingPlan({ ...editingPlan, name: e.target.value })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs font-bold"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-bold text-slate-700 dark:text-slate-300 block mb-1">Harga (Rp)</label>
                  <input
                    type="number"
                    required
                    value={editingPlan.price}
                    onChange={e => setEditingPlan({ ...editingPlan, price: Number(e.target.value) })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs font-black"
                  />
                </div>

                <div>
                  <label className="text-xs font-bold text-slate-700 dark:text-slate-300 block mb-1">Periode</label>
                  <input
                    type="text"
                    required
                    value={editingPlan.period}
                    onChange={e => setEditingPlan({ ...editingPlan, period: e.target.value })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <div>
                  <label className="text-xs font-bold text-slate-700 dark:text-slate-300 block mb-1">Limit Pesan WA / Hari</label>
                  <input
                    type="number"
                    required
                    value={editingPlan.daily_msg_limit}
                    onChange={e => setEditingPlan({ ...editingPlan, daily_msg_limit: Number(e.target.value) })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs font-bold text-emerald-600"
                  />
                </div>

                <div>
                  <label className="text-xs font-bold text-slate-700 dark:text-slate-300 block mb-1">Limit Pesan WA / Bulan</label>
                  <input
                    type="number"
                    value={editingPlan.monthly_msg_limit || 0}
                    onChange={e => setEditingPlan({ ...editingPlan, monthly_msg_limit: Number(e.target.value) })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-xs font-bold"
                  />
                </div>

                <div>
                  <label className="text-xs font-bold text-slate-700 dark:text-slate-300 block mb-1">Maksimal Sesi WA</label>
                  <input
                    type="number"
                    value={1}
                    readOnly
                    disabled
                    title="Semua paket dibatasi 1 nomor WhatsApp per akun"
                    className="w-full bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl p-2.5 text-xs font-bold text-slate-500 cursor-not-allowed"
                  />
                  <span className="text-[10px] text-slate-400 block mt-1">1 Nomor / Akun (Semua Paket)</span>
                </div>
              </div>

              {/* Batas Respon Meta AI WhatsApp Per Hari & Per Bulan */}
              <div className="p-3 bg-indigo-50/50 dark:bg-indigo-950/20 border border-indigo-200/60 dark:border-indigo-800/60 rounded-2xl space-y-2">
                <div className="flex items-center space-x-1.5 text-xs font-black text-indigo-700 dark:text-indigo-300">
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Batas Kuota Respon Meta AI WhatsApp (Otomatis)</span>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-[11px] font-bold text-slate-700 dark:text-slate-300 block mb-1">Batas Respon AI / Hari</label>
                    <input
                      type="number"
                      required
                      value={editingPlan.daily_ai_limit ?? 50}
                      onChange={e => setEditingPlan({ ...editingPlan, daily_ai_limit: Number(e.target.value) })}
                      className="w-full bg-white dark:bg-slate-900 border border-indigo-200 dark:border-indigo-800 rounded-xl p-2.5 text-xs font-bold text-indigo-600 dark:text-indigo-400"
                    />
                  </div>

                  <div>
                    <label className="text-[11px] font-bold text-slate-700 dark:text-slate-300 block mb-1">Batas Respon AI / Bulan</label>
                    <input
                      type="number"
                      required
                      value={editingPlan.monthly_ai_limit ?? 1500}
                      onChange={e => setEditingPlan({ ...editingPlan, monthly_ai_limit: Number(e.target.value) })}
                      className="w-full bg-white dark:bg-slate-900 border border-indigo-200 dark:border-indigo-800 rounded-xl p-2.5 text-xs font-bold text-indigo-600 dark:text-indigo-400"
                    />
                  </div>
                </div>
              </div>

              <div>
                <label className="text-xs font-bold text-slate-700 dark:text-slate-300 block mb-1">
                  Fitur-fitur (Pisahkan dengan baris baru)
                </label>
                <textarea
                  rows={4}
                  value={editingPlan.features.join('\n')}
                  onChange={e => setEditingPlan({ ...editingPlan, features: e.target.value.split('\n').filter(Boolean) })}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-3 text-xs"
                />
              </div>

              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="popular_plan"
                  checked={Boolean(editingPlan.popular)}
                  onChange={e => setEditingPlan({ ...editingPlan, popular: e.target.checked })}
                  className="rounded text-emerald-600"
                />
                <label htmlFor="popular_plan" className="text-xs font-bold text-slate-700 dark:text-slate-300">
                  Tandai sebagai Paket Paling Laris (Badge Populer)
                </label>
              </div>

              <div className="flex justify-end space-x-2 pt-4 border-t border-slate-100 dark:border-slate-800">
                <button
                  type="button"
                  onClick={() => {
                    setShowPlanModal(false);
                    setEditingPlan(null);
                  }}
                  className="px-4 py-2 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 rounded-xl text-xs font-bold"
                >
                  Batal
                </button>
                <button
                  type="submit"
                  disabled={isSavingPlan}
                  className="px-5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-black shadow-md"
                >
                  Simpan Perubahan
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Confirmation Modal */}
      <ConfirmModal
        isOpen={confirmModal.isOpen}
        title={confirmModal.title}
        message={confirmModal.message}
        onConfirm={confirmModal.onConfirm}
        onCancel={() => setConfirmModal(prev => ({ ...prev, isOpen: false }))}
      />
    </div>
  );
};
