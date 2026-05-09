window.addEventListener('load', function() {
  const loadingOverlay = document.getElementById('loadingOverlay');
  const app = document.getElementById('app');
  
  setTimeout(() => {
    loadingOverlay.style.opacity = '0';
    app.style.opacity = '1';
    setTimeout(() => {
      loadingOverlay.style.display = 'none';
    }, 500);
  }, 1500);
});

if ('serviceWorker' in navigator) {
  let registration;
  
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    Swal.fire({
      title: 'Update Complete',
      text: 'A new version has been loaded. Refresh to see the latest changes?',
      icon: 'success',
      background: document.documentElement.classList.contains('dark') ? '#1e293b' : '#ffffff',
      color: document.documentElement.classList.contains('dark') ? '#ffffff' : '#000000',
      showCancelButton: true,
      confirmButtonText: 'Refresh Now',
      cancelButtonText: 'Later',
      allowOutsideClick: false
    }).then((result) => {
      if (result.isConfirmed) {
        window.location.reload();
      }
    });
  });

  navigator.serviceWorker.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'UPDATE_AVAILABLE') {
      Swal.fire({
        title: 'Update Available',
        text: 'A new version is available. Would you like to update now?',
        icon: 'info',
        background: document.documentElement.classList.contains('dark') ? '#1e293b' : '#ffffff',
        color: document.documentElement.classList.contains('dark') ? '#ffffff' : '#000000',
        showCancelButton: true,
        confirmButtonText: 'Update Now',
        cancelButtonText: 'Later',
        allowOutsideClick: false
      }).then((result) => {
        if (result.isConfirmed) {
          if (registration && registration.waiting) {
            registration.waiting.postMessage({ type: 'SKIP_WAITING' });
          }
        }
      });
    }
  });

  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
      .then((reg) => {
        registration = reg;
        console.log('SW registered:', reg);
        reg.update().then(() => {
          console.log('Checked for updates on registration');
        });
        
        if (reg.waiting) {
          Swal.fire({
            title: 'Update Available',
            text: 'A new version is ready. Would you like to update now?',
            icon: 'info',
            background: document.documentElement.classList.contains('dark') ? '#1e293b' : '#ffffff',
            color: document.documentElement.classList.contains('dark') ? '#ffffff' : '#000000',
            showCancelButton: true,
            confirmButtonText: 'Update Now',
            cancelButtonText: 'Later',
            allowOutsideClick: false
          }).then((result) => {
            if (result.isConfirmed) {
              reg.waiting.postMessage({ type: 'SKIP_WAITING' });
            }
          });
        }
        
        reg.onupdatefound = () => {
          const installingWorker = reg.installing;
          installingWorker.onstatechange = () => {
            if (installingWorker.state === 'installed' && navigator.serviceWorker.controller) {
              Swal.fire({
                title: 'Update Ready',
                text: 'A new version is ready to install. Update now?',
                icon: 'info',
                background: document.documentElement.classList.contains('dark') ? '#1e293b' : '#ffffff',
                color: document.documentElement.classList.contains('dark') ? '#ffffff' : '#000000',
                showCancelButton: true,
                confirmButtonText: 'Update Now',
                cancelButtonText: 'Later',
                allowOutsideClick: false
              }).then((result) => {
                if (result.isConfirmed) {
                  installingWorker.postMessage({ type: 'SKIP_WAITING' });
                }
              });
            }
          };
        };
      })
      .catch((err) => console.log('SW registration failed:', err));
  });
}

window.addEventListener('error', function(event) {
  console.error('Global error:', event.error || event.message, 'at', event.filename, 'line', event.lineno);
});

const { createApp, ref, onMounted } = Vue;

createApp({
  setup() {
    const currentPage = ref('login');
    const loadingStates = ref({
      login: false,
      follow: false,
      reactions: false,
      share: false,
      guardOn: false,
      guardOff: false,
      sessionCheck: true
    });
    
    const user = ref({
      id: '',
      name: '',
      token: '',
      cookies: '',
      sessionToken: ''
    });
    
    const savedAccounts = ref([]);
    const showAccountSwitcher = ref(false);
    const cooldownTime = ref(0);
    
    const loginForm = ref({
      username: '',
      password: ''
    });
    
    const followForm = ref({
      link: '',
      limit: '5'
    });
    
    const reactionForm = ref({
      link: '',
      type: 'WOW',
      limit: '5'
    });
    
    const shareForm = ref({
      link: '',
      delay: '5',
      limit: '100'
    });

    // Device identification for persistent sessions
    const getDeviceToken = () => {
      let deviceToken = localStorage.getItem('deviceToken');
      if (!deviceToken) {
        deviceToken = generateDeviceToken();
        localStorage.setItem('deviceToken', deviceToken);
      }
      return deviceToken;
    };

    const generateDeviceToken = () => {
      const array = new Uint8Array(32);
      crypto.getRandomValues(array);
      return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    };

    const saveSessionToLocalStorage = (sessionData) => {
      try {
        const sessions = JSON.parse(localStorage.getItem('sessions') || '{}');
        sessions[sessionData.userId] = {
          userId: sessionData.userId,
          name: sessionData.name,
          sessionToken: sessionData.sessionToken,
          lastLogin: new Date().toISOString()
        };
        localStorage.setItem('sessions', JSON.stringify(sessions));
        updateSavedAccountsList();
      } catch (error) {
        console.error('Error saving session:', error);
      }
    };

    const removeSessionFromLocalStorage = (userId) => {
      try {
        const sessions = JSON.parse(localStorage.getItem('sessions') || '{}');
        delete sessions[userId];
        localStorage.setItem('sessions', JSON.stringify(sessions));
        updateSavedAccountsList();
      } catch (error) {
        console.error('Error removing session:', error);
      }
    };

    const updateSavedAccountsList = () => {
      try {
        const sessions = JSON.parse(localStorage.getItem('sessions') || '{}');
        savedAccounts.value = Object.values(sessions).sort((a, b) => 
          new Date(b.lastLogin) - new Date(a.lastLogin)
        );
      } catch (error) {
        console.error('Error updating accounts list:', error);
        savedAccounts.value = [];
      }
    };

    const formatDate = (dateString) => {
      if (!dateString) return 'Unknown';
      const date = new Date(dateString);
      const now = new Date();
      const diff = now - date;
      
      if (diff < 60000) return 'Just now';
      if (diff < 3600000) return Math.floor(diff / 60000) + ' minutes ago';
      if (diff < 86400000) return Math.floor(diff / 3600000) + ' hours ago';
      return date.toLocaleDateString();
    };

    const checkSession = async () => {
      try {
        updateSavedAccountsList();
        
        // Check for active sessions in localStorage
        const sessions = JSON.parse(localStorage.getItem('sessions') || '{}');
        const sessionKeys = Object.keys(sessions);
        
        if (sessionKeys.length > 0) {
          // Try the most recent session first
          const mostRecent = savedAccounts.value[0];
          if (mostRecent && mostRecent.sessionToken) {
            try {
              const response = await axios.get('/api/session', {
                headers: { 'Authorization': 'Bearer ' + mostRecent.sessionToken }
              });
              
              if (response.data.success) {
                user.value = response.data.user;
                currentPage.value = 'dashboard';
                return;
              }
            } catch (error) {
              // Session expired, remove from localStorage
              removeSessionFromLocalStorage(mostRecent.userId);
            }
          }
        }
      } catch (error) {
        console.error('Session check error:', error);
      } finally {
        loadingStates.value.sessionCheck = false;
      }
    };

    const switchAccount = (account) => {
      if (account.userId === user.value.id) {
        showAccountSwitcher.value = false;
        return;
      }
      switchToAccount(account);
    };

    const switchToAccount = async (account) => {
      try {
        const response = await axios.post('/api/accounts/switch', {
          userId: account.userId,
          sessionToken: account.sessionToken
        });
        
        if (response.data.success) {
          user.value = response.data.user;
          showAccountSwitcher.value = false;
          
          // Update last login timestamp
          saveSessionToLocalStorage({
            userId: user.value.id,
            name: user.value.name,
            sessionToken: user.value.sessionToken
          });
          
          Swal.fire({
            title: 'Success',
            text: 'Switched to ' + user.value.name,
            icon: 'success',
            background: '#1e293b',
            color: '#ffffff'
          });
        }
      } catch (error) {
        console.error('Switch account error:', error);
        Swal.fire({
          title: 'Error',
          text: 'Failed to switch account. Please login again.',
          icon: 'error',
          background: '#1e293b',
          color: '#ffffff'
        });
      }
    };

    const getCooldownMessage = () => {
      const tool = localStorage.getItem('cooldownTool');
      const baseMessage = 'Please wait for ' + cooldownTime.value + ' minutes before submitting again.';
      
      if (tool === 'follow') {
        return 'Auto Follower tool is cooling down. ' + baseMessage;
      } else if (tool === 'reactions') {
        return 'Auto Reactions tool is cooling down. ' + baseMessage;
      }
      return baseMessage;
    };

    onMounted(() => {
      checkSession();
    });

    const handleLogin = async () => {
      try {
        loadingStates.value.login = true;
        
        const response = await axios.post('/api/login', {
          email: loginForm.value.username,
          password: loginForm.value.password
        });
        
        if (response.data.success) {
          user.value = {
            id: response.data.userId,
            name: response.data.name || 'Facebook User',
            token: response.data.accessToken,
            cookies: response.data.cookies || '',
            sessionToken: response.data.sessionToken
          };
          
          // Save session for persistent login
          saveSessionToLocalStorage({
            userId: response.data.userId,
            name: response.data.name,
            sessionToken: response.data.sessionToken
          });
          
          currentPage.value = 'dashboard';
          
          Swal.fire({
            title: 'Success',
            text: 'Logged in successfully!',
            icon: 'success',
            background: '#1e293b',
            color: '#ffffff'
          });
        } else {
          throw new Error(response.data.error || 'Login failed');
        }
      } catch (error) {
        console.error('Login error:', error);
        let errorMessage = 'Login failed. Please check your credentials.';
        if (error.response) {
          errorMessage = error.response.data?.error || error.response.data?.message || errorMessage;
        } else if (error.request) {
          errorMessage = 'Network error - please check your internet connection';
        }
        
        Swal.fire({
          title: 'Error',
          text: errorMessage,
          icon: 'error',
          background: '#1e293b',
          color: '#ffffff'
        });
      } finally {
        loadingStates.value.login = false;
      }
    };

    const logout = async () => {
      try {
        await axios.post('/api/logout', {}, {
          headers: { 'Authorization': 'Bearer ' + user.value.sessionToken }
        });
        
        // Remove from localStorage but keep other accounts
        removeSessionFromLocalStorage(user.value.id);
        
        // Check if there are other saved accounts
        if (savedAccounts.value.length > 0) {
          currentPage.value = 'login';
        } else {
          currentPage.value = 'login';
        }
        
        user.value = {
          id: '',
          name: '',
          token: '',
          cookies: '',
          sessionToken: ''
        };
      } catch (error) {
        console.error('Logout error:', error);
        currentPage.value = 'login';
      }
    };

    const navigateTo = (page) => {
      currentPage.value = page;
      showAccountSwitcher.value = false;
    };

    const submitFollowRequest = async () => {
      try {
        loadingStates.value.follow = true;
        const response = await axios.post('/api/follow', {
          link: followForm.value.link,
          limit: followForm.value.limit
        }, {
          headers: { 'Authorization': 'Bearer ' + user.value.sessionToken }
        });
        
        if (response.data.cooldown) {
          cooldownTime.value = response.data.cooldown;
          currentPage.value = 'cooldown';
          localStorage.setItem('cooldownTool', 'follow');
        } else {
          Swal.fire({
            title: 'Success',
            text: 'Successfully sent ' + response.data.count + ' follows',
            icon: 'success',
            background: '#1e293b',
            color: '#ffffff'
          });
        }
      } catch (error) {
        if (error.response?.data?.cooldown) {
          cooldownTime.value = error.response.data.cooldown;
          currentPage.value = 'cooldown';
          localStorage.setItem('cooldownTool', 'follow');
        } else {
          Swal.fire({
            title: 'Error',
            text: error.response?.data?.message || 'Failed to send follows',
            icon: 'error',
            background: '#1e293b',
            color: '#ffffff'
          });
        }
      } finally {
        loadingStates.value.follow = false;
      }
    };

    const submitReactionRequest = async () => {
      try {
        loadingStates.value.reactions = true;
        const response = await axios.post('/api/reactions', {
          link: reactionForm.value.link,
          type: reactionForm.value.type,
          limit: reactionForm.value.limit
        }, {
          headers: { 'Authorization': 'Bearer ' + user.value.sessionToken }
        });
        
        if (response.data.cooldown) {
          cooldownTime.value = response.data.cooldown;
          currentPage.value = 'cooldown';
          localStorage.setItem('cooldownTool', 'reactions');
        } else {
          Swal.fire({
            title: 'Success',
            text: 'Successfully sent ' + response.data.count + ' reactions',
            icon: 'success',
            background: '#1e293b',
            color: '#ffffff'
          });
        }
      } catch (error) {
        if (error.response?.data?.cooldown) {
          cooldownTime.value = error.response.data.cooldown;
          currentPage.value = 'cooldown';
          localStorage.setItem('cooldownTool', 'reactions');
        } else {
          Swal.fire({
            title: 'Error',
            text: error.response?.data?.message || 'Failed to send reactions',
            icon: 'error',
            background: '#1e293b',
            color: '#ffffff'
          });
        }
      } finally {
        loadingStates.value.reactions = false;
      }
    };

    const submitShareRequest = async () => {
      try {
        loadingStates.value.share = true;
        Swal.fire({
          title: 'Sharing Started',
          text: 'Please wait while shares are being sent...',
          icon: 'success',
          background: '#1e293b',
          color: '#ffffff'
        });
        
        const response = await axios.post('/api/share', {
          link: shareForm.value.link,
          delay: shareForm.value.delay * 1000,
          limit: shareForm.value.limit
        }, {
          headers: { 'Authorization': 'Bearer ' + user.value.sessionToken }
        });
        
        if (response.data.success) {
          Swal.fire({
            title: 'Success',
            text: 'Successfully sent ' + response.data.count + ' shares',
            icon: 'success',
            background: '#1e293b',
            color: '#ffffff'
          });
        } else {
          Swal.fire({
            title: 'Partial Success',
            text: 'Shares completed with ' + response.data.count + ' successes out of ' + response.data.totalAttempted,
            icon: 'info',
            background: '#1e293b',
            color: '#ffffff'
          });
        }
      } catch (error) {
        Swal.fire({
          title: 'Error',
          text: error.response?.data?.error || 'Failed to start sharing process',
          icon: 'error',
          background: '#1e293b',
          color: '#ffffff'
        });
      } finally {
        loadingStates.value.share = false;
      }
    };

    const activateProfileGuard = async () => {
      try {
        loadingStates.value.guardOn = true;
        await axios.post('/api/profile-guard', { action: 'activate' }, {
          headers: { 'Authorization': 'Bearer ' + user.value.sessionToken }
        });
        
        Swal.fire({
          title: 'Success',
          text: 'Profile guard activated successfully',
          icon: 'success',
          background: '#1e293b',
          color: '#ffffff'
        });
      } catch (error) {
        Swal.fire({
          title: 'Error',
          text: error.response?.data?.message || 'Failed to activate profile guard',
          icon: 'error',
          background: '#1e293b',
          color: '#ffffff'
        });
      } finally {
        loadingStates.value.guardOn = false;
      }
    };

    const deactivateProfileGuard = async () => {
      try {
        loadingStates.value.guardOff = true;
        await axios.post('/api/profile-guard', { action: 'deactivate' }, {
          headers: { 'Authorization': 'Bearer ' + user.value.sessionToken }
        });
        
        Swal.fire({
          title: 'Success',
          text: 'Profile guard deactivated successfully',
          icon: 'success',
          background: '#1e293b',
          color: '#ffffff'
        });
      } catch (error) {
        Swal.fire({
          title: 'Error',
          text: error.response?.data?.message || 'Failed to deactivate profile guard',
          icon: 'error',
          background: '#1e293b',
          color: '#ffffff'
        });
      } finally {
        loadingStates.value.guardOff = false;
      }
    };

    return {
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
      handleLogin,
      logout,
      navigateTo,
      switchAccount,
      switchToAccount,
      submitFollowRequest,
      submitReactionRequest,
      submitShareRequest,
      activateProfileGuard,
      deactivateProfileGuard,
      getCooldownMessage,
      formatDate
    };
  }
}).mount('#app');

// PWA Installation logic
document.addEventListener('DOMContentLoaded', () => {
  let deferredPrompt;
  const installModal = document.getElementById('pwaInstallModal');
  const installConfirm = document.getElementById('pwaInstallConfirm');
  const installCancel = document.getElementById('pwaInstallCancel');
  const manualInstall = document.getElementById('pwaManualInstall');
  
  const isStandalone = window.matchMedia('(display-mode: standalone)').matches;
  if (isStandalone) {
    console.log('App is running as PWA');
    return;
  }
  
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    
    installModal.classList.add('active');
    
    setTimeout(() => {
      if (deferredPrompt) {
        manualInstall.classList.add('show');
      }
    }, 3000);
  });
  
  installConfirm.addEventListener('click', async () => {
    if (!deferredPrompt) return;
    
    installModal.classList.remove('active');
    deferredPrompt.prompt();
    
    const { outcome } = await deferredPrompt.userChoice;
    console.log('User response: ' + outcome);
    deferredPrompt = null;
  });
  
  installCancel.addEventListener('click', () => {
    installModal.classList.remove('active');
  });
  
  manualInstall.addEventListener('click', async () => {
    if (deferredPrompt) {
      deferredPrompt.prompt();
      const { outcome } = await deferredPrompt.userChoice;
      console.log('User response: ' + outcome);
      
      if (outcome === 'accepted') {
        manualInstall.classList.remove('show');
      }
    } else {
      Swal.fire({
        title: 'Install App',
        text: 'To install this app, look for the "Add to Home Screen" option in your browser\'s menu.',
        icon: 'info',
        background: document.documentElement.classList.contains('dark') ? '#1e293b' : '#ffffff',
        color: document.documentElement.classList.contains('dark') ? '#ffffff' : '#000000'
      });
    }
  });
  
  window.addEventListener('appinstalled', () => {
    installModal.classList.remove('active');
    manualInstall.classList.remove('show');
    console.log('PWA was installed');
  });
});