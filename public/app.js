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

// Dynamic PWA publisher name
const publisherElement = document.getElementById('pwaPublisher');
if (publisherElement) {
  const hostname = window.location.hostname;
  const cleanHostname = hostname.replace(/^www\./, '');
  publisherElement.textContent = cleanHostname;
}

// PWA Installation logic (only once)
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
  
  if (installConfirm) {
    installConfirm.addEventListener('click', async () => {
      if (!deferredPrompt) return;
      
      installModal.classList.remove('active');
      deferredPrompt.prompt();
      
      const { outcome } = await deferredPrompt.userChoice;
      console.log('User response: ' + outcome);
      deferredPrompt = null;
    });
  }
  
  if (installCancel) {
    installCancel.addEventListener('click', () => {
      installModal.classList.remove('active');
    });
  }
  
  if (manualInstall) {
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
  }
  
  window.addEventListener('appinstalled', () => {
    installModal.classList.remove('active');
    if (manualInstall) manualInstall.classList.remove('show');
    console.log('PWA was installed');
  });
});

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
      email: '',
      name: '',
      token: '',
      cookies: '',
      sessionToken: ''
    });
    
    const savedAccounts = ref([]);
    const showAccountSwitcher = ref(false);
    const cooldownTime = ref(0);
    const needsFacebookReauth = ref(false);
    
    const loginForm = ref({
      email: '',
      password: ''
    });
    
    const reauthForm = ref({
      facebookEmail: '',
      facebookPassword: ''
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
        sessions[sessionData.email] = {
          email: sessionData.email,
          name: sessionData.name,
          facebookId: sessionData.id,
          sessionToken: sessionData.sessionToken,
          lastLogin: new Date().toISOString()
        };
        localStorage.setItem('sessions', JSON.stringify(sessions));
        updateSavedAccountsList();
      } catch (error) {
        console.error('Error saving session:', error);
      }
    };

    const removeSessionFromLocalStorage = (email) => {
      try {
        const sessions = JSON.parse(localStorage.getItem('sessions') || '{}');
        delete sessions[email];
        localStorage.setItem('sessions', JSON.stringify(sessions));
        updateSavedAccountsList();
      } catch (error) {
        console.error('Error removing session:', error);
      }
    };

    const updateSavedAccountsList = async () => {
      try {
        // Get accounts from localStorage only (device/browser specific)
        const sessions = JSON.parse(localStorage.getItem('sessions') || '{}');
        const accounts = Object.values(sessions).sort((a, b) => 
          new Date(b.lastLogin) - new Date(a.lastLogin)
        );
        savedAccounts.value = accounts;
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

    const getProfilePictureUrl = (facebookId, accessToken = null) => {
      if (!facebookId) return '';
      // Return proxy endpoint instead of direct Facebook URL
      return `/api/avatar/${facebookId}`;
    };

    const checkSession = async () => {
      try {
        await updateSavedAccountsList();
        
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
                user.value.sessionToken = mostRecent.sessionToken;
                currentPage.value = 'dashboard';
                
                // Show toast notification for auto-login
                Swal.fire({
                  title: 'Welcome back!',
                  text: `Logged in as ${user.value.name}`,
                  icon: 'success',
                  toast: true,
                  position: 'top-end',
                  showConfirmButton: false,
                  timer: 3000,
                  background: '#1e293b',
                  color: '#ffffff'
                });
                return;
              }
            } catch (error) {
              // Session expired, remove from localStorage
              if (mostRecent.email) {
                removeSessionFromLocalStorage(mostRecent.email);
              }
            }
          }
        }
      } catch (error) {
        console.error('Session check error:', error);
      } finally {
        loadingStates.value.sessionCheck = false;
      }
    };

    const switchAccount = async (account) => {
      if (account.email === user.value.email) {
        showAccountSwitcher.value = false;
        return;
      }
      await switchToAccount(account);
    };

    const switchToAccount = async (account) => {
      try {
        loadingStates.value.login = true;
        
        const response = await axios.post('/api/accounts/switch', {
          email: account.email,
          sessionToken: account.sessionToken
        });
        
        if (response.data.success) {
          user.value = response.data.user;
          user.value.sessionToken = response.data.user.sessionToken;
          showAccountSwitcher.value = false;
          
          // Update last login timestamp in localStorage
          saveSessionToLocalStorage({
            email: user.value.email,
            name: user.value.name,
            id: user.value.id,
            sessionToken: user.value.sessionToken
          });
          
          // Show success toast
          Swal.fire({
            title: 'Success',
            text: `Switched to ${user.value.name}`,
            icon: 'success',
            toast: true,
            position: 'top-end',
            showConfirmButton: false,
            timer: 3000,
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
      } finally {
        loadingStates.value.login = false;
      }
    };

    const loginWithSavedAccount = async (account) => {
      if (!account.sessionToken) {
        Swal.fire({
          title: 'Error',
          text: 'Invalid session. Please login manually.',
          icon: 'error',
          background: '#1e293b',
          color: '#ffffff'
        });
        return;
      }
      
      loadingStates.value.login = true;
      
      try {
        const response = await axios.get('/api/session', {
          headers: { 'Authorization': 'Bearer ' + account.sessionToken }
        });
        
        if (response.data.success) {
          user.value = response.data.user;
          user.value.sessionToken = account.sessionToken;
          currentPage.value = 'dashboard';
          
          // Update last login
          saveSessionToLocalStorage({
            email: user.value.email,
            name: user.value.name,
            id: user.value.id,
            sessionToken: user.value.sessionToken
          });
          
          Swal.fire({
            title: 'Welcome back!',
            text: `Logged in as ${user.value.name}`,
            icon: 'success',
            toast: true,
            position: 'top-end',
            showConfirmButton: false,
            timer: 3000,
            background: '#1e293b',
            color: '#ffffff'
          });
        } else {
          // Session expired, remove from localStorage
          removeSessionFromLocalStorage(account.email);
          Swal.fire({
            title: 'Session Expired',
            text: 'Please login again manually.',
            icon: 'warning',
            background: '#1e293b',
            color: '#ffffff'
          });
        }
      } catch (error) {
        console.error('Auto-login error:', error);
        removeSessionFromLocalStorage(account.email);
        Swal.fire({
          title: 'Login Failed',
          text: 'Could not login with saved account. Please login manually.',
          icon: 'error',
          background: '#1e293b',
          color: '#ffffff'
        });
      } finally {
        loadingStates.value.login = false;
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
          email: loginForm.value.email,
          password: loginForm.value.password
        });
        
        if (response.data.success) {
          user.value = {
            id: response.data.userId,
            email: response.data.email,
            name: response.data.name || 'Facebook User',
            token: response.data.accessToken,
            cookies: response.data.cookies || '',
            sessionToken: response.data.sessionToken
          };
          
          // Save session for persistent login
          saveSessionToLocalStorage({
            email: response.data.email,
            name: response.data.name,
            id: response.data.userId,
            sessionToken: response.data.sessionToken
          });
          
          currentPage.value = 'dashboard';
          needsFacebookReauth.value = false;
          
          Swal.fire({
            title: 'Success',
            text: 'Logged in successfully!',
            icon: 'success',
            background: '#1e293b',
            color: '#ffffff'
          });
        }
      } catch (error) {
        console.error('Login error:', error);
        let errorMessage = 'Login failed. Please check your credentials.';
        
        if (error.response) {
          if (error.response.data.needsFacebookReauth) {
            needsFacebookReauth.value = true;
            errorMessage = 'Your Facebook session has expired. Please re-enter your Facebook credentials.';
            
            const { value: formData } = await Swal.fire({
              title: 'Facebook Session Expired',
              html: `
                <input type="text" id="facebookEmail" class="swal2-input" placeholder="Facebook Email/Phone">
                <input type="password" id="facebookPassword" class="swal2-input" placeholder="Facebook Password">
              `,
              focusConfirm: false,
              background: '#1e293b',
              color: '#ffffff',
              preConfirm: () => {
                const facebookEmail = document.getElementById('facebookEmail').value;
                const facebookPassword = document.getElementById('facebookPassword').value;
                if (!facebookEmail || !facebookPassword) {
                  Swal.showValidationMessage('Please enter both Facebook email and password');
                }
                return { facebookEmail, facebookPassword };
              }
            });
            
            if (formData) {
              try {
                const reauthResponse = await axios.post('/api/reauth', {
                  email: loginForm.value.email,
                  appPassword: loginForm.value.password,
                  facebookEmail: formData.facebookEmail,
                  facebookPassword: formData.facebookPassword
                });
                
                if (reauthResponse.data.success) {
                  user.value = {
                    id: reauthResponse.data.userId,
                    email: reauthResponse.data.email,
                    name: reauthResponse.data.name,
                    token: reauthResponse.data.accessToken,
                    cookies: reauthResponse.data.cookies,
                    sessionToken: reauthResponse.data.sessionToken
                  };
                  
                  saveSessionToLocalStorage({
                    email: reauthResponse.data.email,
                    name: reauthResponse.data.name,
                    id: reauthResponse.data.userId,
                    sessionToken: reauthResponse.data.sessionToken
                  });
                  
                  currentPage.value = 'dashboard';
                  needsFacebookReauth.value = false;
                  
                  Swal.fire({
                    title: 'Success',
                    text: 'Re-authenticated successfully!',
                    icon: 'success',
                    background: '#1e293b',
                    color: '#ffffff'
                  });
                }
              } catch (reauthError) {
                Swal.fire({
                  title: 'Error',
                  text: 'Re-authentication failed. Please check your Facebook credentials.',
                  icon: 'error',
                  background: '#1e293b',
                  color: '#ffffff'
                });
              }
            }
          } else {
            errorMessage = error.response.data?.error || error.response.data?.message || errorMessage;
            Swal.fire({
              title: 'Error',
              text: errorMessage,
              icon: 'error',
              background: '#1e293b',
              color: '#ffffff'
            });
          }
        } else if (error.request) {
          errorMessage = 'Network error - please check your internet connection';
          Swal.fire({
            title: 'Error',
            text: errorMessage,
            icon: 'error',
            background: '#1e293b',
            color: '#ffffff'
          });
        }
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
        removeSessionFromLocalStorage(user.value.email);
        
        // Reset user
        user.value = {
          id: '',
          email: '',
          name: '',
          token: '',
          cookies: '',
          sessionToken: ''
        };
        
        // Refresh account list
        await updateSavedAccountsList();
        
        currentPage.value = 'login';
        
        Swal.fire({
          title: 'Logged Out',
          text: 'You have been logged out successfully.',
          icon: 'success',
          toast: true,
          position: 'top-end',
          showConfirmButton: false,
          timer: 3000,
          background: '#1e293b',
          color: '#ffffff'
        });
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
      needsFacebookReauth,
      loginForm,
      reauthForm,
      followForm,
      reactionForm,
      shareForm,
      handleLogin,
      logout,
      navigateTo,
      switchAccount,
      switchToAccount,
      loginWithSavedAccount,
      submitFollowRequest,
      submitReactionRequest,
      submitShareRequest,
      activateProfileGuard,
      deactivateProfileGuard,
      getCooldownMessage,
      formatDate,
      getProfilePictureUrl
    };
  }
}).mount('#app');
