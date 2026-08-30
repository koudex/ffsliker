/**
 * FFSLiker NEXUS - Premium UI Controller
 * @module app
 * 
 * Features:
 * - Routeless navigation (v-show preserves state)
 * - Real-time SSE progress streaming
 * - Seamless account switching
 * - Soft logout (webapp only)
 * - Responsive PWA
 * 
 * @requires Vue 3
 * @requires Axios
 * @requires SweetAlert2
 */

// ================================================================
// 1. CONFIGURATION & CONSTANTS
// ================================================================

const API_BASE = '/api';
const COOLDOWN_MINUTES = 30;

// ================================================================
// 2. STATE MANAGEMENT
// ================================================================

const state = reactive({
  currentPage: 'login',
  user: { id: '', name: '', email: '', sessionToken: '' },
  savedAccounts: [],
  loading: { login: false, follow: false, reactions: false, share: false },
  progress: {
    follow: { active: false, total: 0, completed: 0, success: 0, failed: 0 },
    reactions: { active: false, total: 0, completed: 0, success: 0, failed: 0 },
    share: { active: false, total: 0, completed: 0, success: 0, failed: 0 }
  }
});

// ================================================================
// 3. API SERVICES
// ================================================================

const api = {
  async login(identifier, password) {
    const response = await axios.post('/api/login', { identifier, password });
    return response.data;
  },
  
  async switchAccount(accountId) {
    const response = await axios.post('/api/accounts/switch', { accountId });
    return response.data;
  },
  
  async logout() {
    const response = await axios.post('/api/logout');
    return response.data;
  },
  
  async startFollow(link, limit) {
    const response = await axios.post('/api/follow', { link, limit });
    return response.data;
  },
  
  async startReaction(link, type, limit) {
    const response = await axios.post('/api/reactions', { link, type, limit });
    return response.data;
  },
  
  async startShare(link, delay, limit) {
    const response = await axios.post('/api/share', { link, delay, limit });
    return response.data;
  },
  
  async getSavedAccounts() {
    const response = await axios.get('/api/accounts/list');
    return response.data;
  }
};

// ================================================================
// 4. UI CONTROLLERS
// ================================================================

const ui = {
  showToast(message, type = 'success') {
    Swal.fire({
      title: type === 'success' ? 'Success' : type === 'error' ? 'Error' : 'Info',
      text: message,
      icon: type,
      toast: true,
      position: 'top-end',
      showConfirmButton: false,
      timer: 3000,
      timerProgressBar: true
    });
  },
  
  showError(message) {
    Swal.fire({
      title: 'Error',
      text: message,
      icon: 'error',
      confirmButtonColor: '#6366f1'
    });
  },
  
  updateProgress(tool, data) {
    const p = state.progress[tool];
    if (!p) return;
    if (typeof data.total === 'number') p.total = data.total;
    if (typeof data.completed === 'number') p.completed = data.completed;
    if (typeof data.success === 'number') p.success = data.success;
    if (typeof data.failed === 'number') p.failed = data.failed;
    if (typeof data.phase === 'string') p.phase = data.phase;
    if (typeof data.message === 'string') p.message = data.message;
    if (data.status === 'complete' || data.status === 'failed') {
      p.active = false;
      if (data.status === 'complete') {
        ui.showToast(`Completed: ${p.success} successful, ${p.failed} failed`);
      }
    }
  }
};

// ================================================================
// 5. VUE APP
// ================================================================

const { createApp, ref, reactive, onMounted, computed } = Vue;

createApp({
  setup() {
    // --- Routing ---
    const currentPage = ref('login');

    // --- User state ---
    const user = ref({
      id: '',
      email: '',
      name: '',
      sessionToken: ''
    });

    // --- Saved accounts ---
    const savedAccounts = ref([]);
    const showAccountSwitcher = ref(false);
    const cooldownTime = ref(0);

    // --- Loading states ---
    const loadingStates = reactive({
      login: false,
      follow: false,
      reactions: false,
      share: false,
      sessionCheck: true
    });

    // --- Forms ---
    const loginForm = ref({ identifier: '', password: '' });
    const followForm = ref({ link: '', limit: '5' });
    const reactionForm = ref({ link: '', type: 'LIKE', limit: '5' });
    const shareForm = ref({ link: '', delay: '5', limit: '100' });

    // --- Progress tracking ---
    const progress = reactive({
      follow:    { active: false, total: 0, completed: 0, success: 0, failed: 0, phase: 'idle', message: '' },
      reactions: { active: false, total: 0, completed: 0, success: 0, failed: 0, phase: 'idle', message: '' },
      share:     { active: false, total: 0, completed: 0, success: 0, failed: 0, phase: 'idle', message: '' }
    });

    // --- SSE connections ---
    const sseConnections = ref({});

    const progressPercent = (tool) => {
      const p = progress[tool];
      if (!p || !p.total) return 0;
      return Math.min(100, Math.round((p.completed / p.total) * 100));
    };

    // ================================================================
    // Account management
    // ================================================================
    
    const updateSavedAccountsList = async () => {
      try {
        const response = await api.getSavedAccounts();
        if (response.success) {
          savedAccounts.value = response.accounts || [];
        }
      } catch (error) {
        console.error('Failed to load saved accounts:', error);
        savedAccounts.value = [];
      }
    };

    const saveSession = async (session) => {
      // Session is saved server-side via HTTP-only cookies
      // This method is kept for API compatibility
      await updateSavedAccountsList();
    };

    // ================================================================
    // SSE progress watcher
    // ================================================================
    
    const watchTaskProgress = (tool, taskId) => {
      // Close any existing connection for this tool
      if (sseConnections.value[tool]) {
        try { sseConnections.value[tool].close(); } catch (e) {}
      }

      const p = progress[tool];
      p.active = true;
      p.phase = 'connecting';

      // Prefer SSE
      let es = null;
      try {
        es = new EventSource(`/api/task/${taskId}/stream`);
        sseConnections.value[tool] = es;

        es.onmessage = (ev) => {
          try {
            const d = JSON.parse(ev.data);
            ui.updateProgress(tool, d);
          } catch (e) {}
        };
        es.addEventListener('end', () => {
          closeSse(tool);
        });
        es.onerror = () => {
          closeSse(tool);
          startPolling(tool, taskId);
        };
      } catch (e) {
        startPolling(tool, taskId);
      }
    };

    const startPolling = (tool, taskId) => {
      const interval = setInterval(async () => {
        try {
          const r = await axios.get(`/api/task/${taskId}/status`);
          if (r.data && r.data.success) {
            ui.updateProgress(tool, r.data);
            if (r.data.status === 'complete' || r.data.status === 'failed') {
              clearInterval(interval);
            }
          }
        } catch (e) {
          clearInterval(interval);
        }
      }, 1500);
      sseConnections.value[tool + '_poll'] = interval;
    };

    const closeSse = (tool) => {
      if (sseConnections.value[tool]) {
        try { sseConnections.value[tool].close(); } catch (e) {}
        delete sseConnections.value[tool];
      }
      if (sseConnections.value[tool + '_poll']) {
        clearInterval(sseConnections.value[tool + '_poll']);
        delete sseConnections.value[tool + '_poll'];
      }
    };

    const resetProgress = (tool) => {
      const p = progress[tool];
      p.active = false;
      p.total = 0;
      p.completed = 0;
      p.success = 0;
      p.failed = 0;
      p.phase = 'idle';
      p.message = '';
    };

    // ================================================================
    // Session check on boot
    // ================================================================
    
    const checkSession = async () => {
      try {
        await updateSavedAccountsList();
        if (savedAccounts.value.length > 0) {
          const mostRecent = savedAccounts.value[0];
          if (mostRecent && mostRecent.id) {
            try {
              const r = await axios.get('/api/session');
              if (r.data && r.data.success) {
                user.value.id = r.data.user?.id || mostRecent.id;
                user.value.name = r.data.user?.name || mostRecent.name || 'Operator';
                user.value.email = r.data.user?.email || mostRecent.email || '';
                user.value.sessionToken = r.data.sessionToken || mostRecent.sessionToken;
                currentPage.value = 'dashboard';
                ui.showToast(`Welcome back, ${user.value.name}`, 'success');
                return;
              }
            } catch (e) {
              // Session expired - fall through to login
            }
          }
        }
      } catch (error) {
        console.error('Session check error:', error);
      } finally {
        loadingStates.sessionCheck = false;
      }
    };

    // ================================================================
    // LOGIN
    // ================================================================
    
    const handleLogin = async () => {
      try {
        loadingStates.login = true;
        const result = await api.login(loginForm.value.identifier, loginForm.value.password);

        if (result.success) {
          user.value.id = result.user?.id || '';
          user.value.name = result.user?.name || 'Operator';
          user.value.email = result.user?.email || '';
          user.value.sessionToken = result.sessionToken || '';

          await saveSession({
            id: user.value.id,
            name: user.value.name,
            email: user.value.email,
            sessionToken: user.value.sessionToken
          });

          loginForm.value.password = '';
          currentPage.value = 'dashboard';
          ui.showToast(`Logged in as ${user.value.name}`, 'success');
        }
      } catch (error) {
        console.error('Login error:', error);
        const msg = error.response?.data?.error || error.response?.data?.message || 'Login failed. Please check your credentials.';
        ui.showError(msg);
      } finally {
        loadingStates.login = false;
      }
    };

    // ================================================================
    // Seamless account switching
    // ================================================================
    
    const loginWithSavedAccount = async (account) => {
      if (!account.id) {
        ui.showError('Invalid session. Please log in manually.');
        return;
      }
      
      loadingStates.login = true;
      try {
        const result = await api.switchAccount(account.id);
        
        if (result.success) {
          user.value.id = result.user?.id || account.id;
          user.value.name = result.user?.name || account.name || 'Operator';
          user.value.email = result.user?.email || account.email || '';
          user.value.sessionToken = result.sessionToken || account.sessionToken;

          await saveSession({
            id: user.value.id,
            name: user.value.name,
            email: user.value.email,
            sessionToken: user.value.sessionToken
          });

          currentPage.value = 'dashboard';
          ui.showToast(`Switched to ${user.value.name}`, 'success');
        }
      } catch (error) {
        console.error('Switch account error:', error);
        ui.showError('Failed to switch account. Please log in manually.');
      } finally {
        loadingStates.login = false;
      }
    };

    const switchToAccount = async (account) => {
      if (account.id === user.value.id) {
        showAccountSwitcher.value = false;
        return;
      }
      showAccountSwitcher.value = false;
      await loginWithSavedAccount(account);
    };

    // ================================================================
    // SOFT LOGOUT — only clears the webapp session
    // ================================================================
    
    const logout = async () => {
      const { isConfirmed } = await Swal.fire({
        title: 'Logout of Webapp?',
        html: '<p style="font-size:0.85rem;line-height:1.5;color:#94a3b8;">This will sign you out of the webapp only.<br>Your access token <b style="color:#6366f1;">remains active in the pool</b> to serve other users.</p>',
        icon: 'question',
        showCancelButton: true,
        confirmButtonText: 'Yes, logout',
        cancelButtonText: 'Cancel',
        confirmButtonColor: '#6366f1',
        cancelButtonColor: '#64748b'
      });
      
      if (!isConfirmed) return;

      try {
        await api.logout();
      } catch (e) {
        console.warn('Logout endpoint error (continuing):', e);
      }

      // Close any SSE connections
      ['follow', 'reactions', 'share'].forEach(closeSse);

      user.value = {
        id: '',
        email: '',
        name: '',
        sessionToken: ''
      };

      await updateSavedAccountsList();
      currentPage.value = 'login';
      ui.showToast('Logged out. Token remains in pool.', 'success');
    };

    // ================================================================
    // Navigation
    // ================================================================
    
    const navigateTo = (page) => {
      currentPage.value = page;
      showAccountSwitcher.value = false;
    };

    // ================================================================
    // SUBMIT: FOLLOW
    // ================================================================
    
    const submitFollowRequest = async () => {
      resetProgress('follow');
      try {
        loadingStates.follow = true;
        const result = await api.startFollow(followForm.value.link, followForm.value.limit);

        if (result.cooldown) {
          cooldownTime.value = result.cooldown;
          currentPage.value = 'cooldown';
          localStorage.setItem('cooldownTool', 'follow');
        } else if (result.taskId) {
          watchTaskProgress('follow', result.taskId);
        } else {
          ui.showToast(`Successfully sent ${result.count || 0} follows`, 'success');
        }
      } catch (error) {
        if (error.response?.data?.cooldown) {
          cooldownTime.value = error.response.data.cooldown;
          currentPage.value = 'cooldown';
          localStorage.setItem('cooldownTool', 'follow');
        } else {
          ui.showError(error.response?.data?.error || error.response?.data?.message || 'Failed to send follows');
          resetProgress('follow');
        }
      } finally {
        loadingStates.follow = false;
      }
    };

    // ================================================================
    // SUBMIT: REACTIONS
    // ================================================================
    
    const submitReactionRequest = async () => {
      resetProgress('reactions');
      try {
        loadingStates.reactions = true;
        const result = await api.startReaction(
          reactionForm.value.link,
          reactionForm.value.type,
          reactionForm.value.limit
        );

        if (result.cooldown) {
          cooldownTime.value = result.cooldown;
          currentPage.value = 'cooldown';
          localStorage.setItem('cooldownTool', 'reactions');
        } else if (result.taskId) {
          watchTaskProgress('reactions', result.taskId);
        } else {
          ui.showToast(`Successfully sent ${result.count || 0} reactions`, 'success');
        }
      } catch (error) {
        if (error.response?.data?.cooldown) {
          cooldownTime.value = error.response.data.cooldown;
          currentPage.value = 'cooldown';
          localStorage.setItem('cooldownTool', 'reactions');
        } else {
          ui.showError(error.response?.data?.error || error.response?.data?.message || 'Failed to send reactions');
          resetProgress('reactions');
        }
      } finally {
        loadingStates.reactions = false;
      }
    };

    // ================================================================
    // SUBMIT: SHARE
    // ================================================================
    
    const submitShareRequest = async () => {
      resetProgress('share');
      try {
        loadingStates.share = true;
        const result = await api.startShare(
          shareForm.value.link,
          shareForm.value.delay * 1000,
          shareForm.value.limit
        );

        if (result.taskId) {
          watchTaskProgress('share', result.taskId);
        } else if (result.success === false) {
          ui.showToast(result.error || `Completed ${result.count}/${result.totalAttempted}`, 'warning');
        } else {
          ui.showToast(`Successfully sent ${result.count || 0} shares`, 'success');
        }
      } catch (error) {
        ui.showError(error.response?.data?.error || error.response?.data?.message || 'Failed to start sharing');
        resetProgress('share');
      } finally {
        loadingStates.share = false;
      }
    };

    // ================================================================
    // Misc
    // ================================================================
    
    const getCooldownMessage = () => {
      const tool = localStorage.getItem('cooldownTool');
      const base = `Please wait ${cooldownTime.value} minutes before submitting again.`;
      if (tool === 'follow')    return `Auto Follower module cooling down. ${base}`;
      if (tool === 'reactions') return `Auto Reaction module cooling down. ${base}`;
      if (tool === 'share')     return `Auto Share module cooling down. ${base}`;
      return base;
    };

    const formatDate = (dateString) => {
      if (!dateString) return 'unknown';
      const date = new Date(dateString);
      const now = new Date();
      const diff = now - date;
      if (diff < 60000) return 'just now';
      if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
      if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
      return date.toLocaleDateString();
    };

    // ================================================================
    // Lifecycle
    // ================================================================
    
    onMounted(() => {
      // Check for existing session via cookie
      checkSession();
      
      // Remove loading overlay
      setTimeout(() => {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
          overlay.style.opacity = '0';
          setTimeout(() => {
            overlay.style.display = 'none';
            document.getElementById('app').style.opacity = '1';
          }, 500);
        }
      }, 1200);
    });

    // ================================================================
    // Expose to template
    // ================================================================
    
    return {
      // state
      currentPage,
      loadingStates,
      user,
      savedAccounts,
      showAccountSwitcher,
      cooldownTime,
      loginForm,
      followForm,
      reactionForm,
      shareForm,
      progress,
      // methods
      progressPercent,
      handleLogin,
      logout,
      navigateTo,
      switchToAccount,
      loginWithSavedAccount,
      submitFollowRequest,
      submitReactionRequest,
      submitShareRequest,
      getCooldownMessage,
      formatDate
    };
  }
}).mount('#app');
