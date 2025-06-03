document.addEventListener('DOMContentLoaded', function() {
    // --- Running containers UI ---
    const runningDiv = document.createElement('div');
    runningDiv.className = 'running-containers';
    runningDiv.innerHTML = '<h2>Running Containers</h2><ul id="container-list"></ul>';
    document.body.insertBefore(runningDiv, document.body.firstChild);

    function refreshContainers() {
        fetch('/containers')
            .then(res => res.json())
            .then(list => {
                const ul = document.getElementById('container-list');
                ul.innerHTML = '';
                if (!list.length) {
                    ul.innerHTML = '<li style="color:#aaa">No running containers</li>';
                }
                list.forEach(c => {
                    const li = document.createElement('li');
                    li.textContent = `${c.name} (${c.image}) [${c.status}] - Port: ${c.host_port || 'N/A'}`;
                    const stopBtn = document.createElement('button');
                    stopBtn.textContent = 'Stop';
                    stopBtn.style.marginLeft = '12px';
                    stopBtn.onclick = function() {
                        fetch('/containers/stop', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ id: c.id })
                        }).then(() => refreshContainers());
                    };
                    li.appendChild(stopBtn);
                    ul.appendChild(li);
                });
            });
    }
    refreshContainers();
    setInterval(refreshContainers, 10000);

    // --- Launch workspace tiles ---
    const tiles = document.querySelectorAll('.workspace-tile');
    if (!tiles.length) {
        console.warn('No workspace tiles found.');
    }
    tiles.forEach(function(tile) {
        tile.addEventListener('click', function() {
            const service = tile.getAttribute('data-service');
            if (!service) {
                alert('No service key found for this tile.');
                return;
            }
            fetch('/api/launch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ service })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    if (data.url) {
                        window.open(data.url, '_blank');
                    } else if (data.host_port) {
                        const proto = data.proto || 'http';
                        const url = `${proto}://localhost:${data.host_port}`;
                        window.open(url, '_blank');
                    } else {
                        alert(data.message);
                    }
                } else {
                    alert('Error: ' + (data.error || 'Unknown error'));
                }
            })
            .catch((e) => {
                alert('Failed to contact server.');
                console.error(e);
            });
        });
    });

    // Sidebar navigation for Password Manager
    const pmBtn = document.querySelector('.sidebar-menu li:nth-child(2)');
    if (pmBtn && !pmBtn.classList.contains('active')) {
        pmBtn.addEventListener('click', function() {
            window.location.href = '/password-manager';
        });
    }
    // Add Password button handler: show the form
    const addBtn = document.getElementById('add-password-btn');
    const addForm = document.getElementById('add-password-form');
    if (addBtn && addForm) {
        addBtn.onclick = function() {
            addForm.style.display = 'block';
        };
    }
    // Cancel button in form: hide the form
    if (addForm) {
        const cancelBtn = addForm.querySelector('button[type="button"]');
        if (cancelBtn) {
            cancelBtn.onclick = function() {
                addForm.style.display = 'none';
            };
        }
    }
    // Export Passwords button handler
    const exportBtn = document.getElementById('export-passwords-btn');
    if (exportBtn) {
        exportBtn.onclick = function() {
            fetch('/passwords.json')
                .then(res => res.blob())
                .then(blob => {
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'passwords.json';
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                });
        };
    }
    // Password generator for add password form
    const genBtn = document.getElementById('generate-password-btn');
    const addPwdInput = document.getElementById('add-password-input');
    if (genBtn && addPwdInput) {
        genBtn.onclick = function(e) {
            e.preventDefault();
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
            const len = Math.floor(Math.random() * 6) + 15; // 15-20 chars
            let pwd = '';
            for (let i = 0; i < len; i++) {
                pwd += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            addPwdInput.value = pwd;
        };
    }

    // --- Floating Settings FAB and Modal Logic ---
    // Remove dynamically created FAB if it exists (to avoid duplicate/conflict)
    let dynamicFab = document.getElementById('settings-fab');
    if (dynamicFab && !dynamicFab.classList.contains('settings-fab-static')) {
        dynamicFab.remove();
    }
    // Instead, use the static FAB from dashboard.html and move it to the center for debug
    let staticFab = document.getElementById('settings-fab');
    if (staticFab) {
        staticFab.classList.add('settings-fab-static');
        staticFab.style.position = 'fixed';
        staticFab.style.left = '50%';
        staticFab.style.top = '50%';
        staticFab.style.transform = 'translate(-50%, -50%)';
        staticFab.style.zIndex = '1200';
        staticFab.style.width = '60px';
        staticFab.style.height = '60px';
        staticFab.style.borderRadius = '50%';
        staticFab.style.background = 'linear-gradient(135deg, #4f8cff 60%, #6ee7b7 100%)';
        staticFab.style.color = '#fff';
        staticFab.style.border = 'none';
        staticFab.style.boxShadow = '0 4px 24px rgba(0,0,0,0.18)';
        staticFab.style.display = 'flex';
        staticFab.style.alignItems = 'center';
        staticFab.style.justifyContent = 'center';
        staticFab.style.fontSize = '2rem';
        staticFab.style.cursor = 'pointer';
        staticFab.style.transition = 'box-shadow 0.2s, background 0.2s, transform 0.2s';
        staticFab.style.outline = 'none';
    }
    // Create modal if not present
    let settingsModal = document.getElementById('settings-modal');
    if (!settingsModal) {
        settingsModal = document.createElement('div');
        settingsModal.id = 'settings-modal';
        settingsModal.className = 'settings-modal';
        settingsModal.innerHTML = `
            <div class="settings-modal-content">
                <button class="settings-modal-close" aria-label="Close settings">&times;</button>
                <div class="settings-modal-tabs">
                    <button class="tab-btn active" data-tab="preferences">Preferences</button>
                    <button class="tab-btn" data-tab="account">Account Settings</button>
                    <button class="tab-btn" data-tab="help">Help & Support</button>
                </div>
                <div class="settings-modal-panels">
                    <div class="tab-panel active" data-tab="preferences">
                        <!-- Preferences content will be included here -->
                        <div id="settings-preferences-include"></div>
                    </div>
                    <div class="tab-panel" data-tab="account">
                        <div id="settings-account-include"></div>
                    </div>
                    <div class="tab-panel" data-tab="help">
                        <div id="settings-help-include"></div>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(settingsModal);
    }
    // Modal open/close logic
    staticFab.addEventListener('click', function() {
        settingsModal.classList.add('open');
        document.body.classList.add('modal-open');
        // Focus first tab
        settingsModal.querySelector('.tab-btn').focus();
    });
    settingsModal.querySelector('.settings-modal-close').addEventListener('click', function() {
        settingsModal.classList.remove('open');
        document.body.classList.remove('modal-open');
    });
    // Close modal on Escape
    document.addEventListener('keydown', function(e) {
        if (settingsModal.classList.contains('open') && e.key === 'Escape') {
            settingsModal.classList.remove('open');
            document.body.classList.remove('modal-open');
        }
    });
    // Tab switching logic
    settingsModal.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            settingsModal.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const tab = btn.getAttribute('data-tab');
            settingsModal.querySelectorAll('.tab-panel').forEach(panel => {
                if (panel.getAttribute('data-tab') === tab) {
                    panel.classList.add('active');
                } else {
                    panel.classList.remove('active');
                }
            });
        });
    });
    // Accessibility: trap focus in modal
    settingsModal.addEventListener('keydown', function(e) {
        if (!settingsModal.classList.contains('open')) return;
        if (e.key === 'Tab') {
            const focusable = settingsModal.querySelectorAll('button, [tabindex]:not([tabindex="-1"])');
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            if (e.shiftKey) {
                if (document.activeElement === first) {
                    last.focus();
                    e.preventDefault();
                }
            } else {
                if (document.activeElement === last) {
                    first.focus();
                    e.preventDefault();
                }
            }
        }
    });
    // Load tab content via includes (if using AJAX, otherwise server-side render)
    // Example: fetch('/preferences').then(...)
    // You can replace this with AJAX if you want dynamic content.

    // Remove old sidebar user modal logic (no longer needed)

    // DEBUG: Add a visible test button to the center of the screen to confirm JS is running
    let debugBtn = document.getElementById('debug-test-btn');
    if (!debugBtn) {
        debugBtn = document.createElement('button');
        debugBtn.id = 'debug-test-btn';
        debugBtn.textContent = 'DEBUG BUTTON';
        debugBtn.style.position = 'fixed';
        debugBtn.style.left = '50%';
        debugBtn.style.top = '60%';
        debugBtn.style.transform = 'translate(-50%, -50%)';
        debugBtn.style.zIndex = '9999';
        debugBtn.style.background = 'red';
        debugBtn.style.color = 'white';
        debugBtn.style.fontSize = '2rem';
        debugBtn.style.padding = '1rem 2rem';
        debugBtn.style.border = 'none';
        debugBtn.style.borderRadius = '1rem';
        document.body.appendChild(debugBtn);
    }

    // Sidebar Settings link logic
    const sidebarSettingsLink = document.getElementById('sidebar-settings-link');
    if (sidebarSettingsLink) {
        sidebarSettingsLink.addEventListener('click', function(e) {
            e.preventDefault();
            let settingsModal = document.getElementById('settings-modal');
            if (!settingsModal) {
                settingsModal = document.createElement('div');
                settingsModal.id = 'settings-modal';
                settingsModal.className = 'settings-modal full-page';
                settingsModal.innerHTML = `
                    <div class="settings-modal-content">
                        <div class="settings-modal-header">
                            <h2><i class="fas fa-cog"></i> Settings</h2>
                            <button class="settings-modal-close" aria-label="Close settings">&times;</button>
                        </div>
                        <div class="settings-modal-tabs">
                            <button class="tab-btn active" data-tab="preferences"><i class="fas fa-sliders-h"></i> Preferences</button>
                            <button class="tab-btn" data-tab="account"><i class="fas fa-user-cog"></i> Account Settings</button>
                            <button class="tab-btn" data-tab="help"><i class="fas fa-question-circle"></i> Help & Support</button>
                        </div>
                        <div class="settings-modal-body">
                            <div class="tab-panel active" data-tab="preferences">
                                {% include 'preferences.html' %}
                            </div>
                            <div class="tab-panel" data-tab="account">
                                {% include 'account_settings.html' %}
                            </div>
                            <div class="tab-panel" data-tab="help">
                                {% include 'help_support.html' %}
                            </div>
                        </div>
                    </div>
                `;
                document.body.appendChild(settingsModal);
            }
            settingsModal.classList.add('open');
            document.body.classList.add('modal-open');
            settingsModal.querySelector('.tab-btn').focus();
            // Modal close logic
            settingsModal.querySelector('.settings-modal-close').onclick = function() {
                settingsModal.classList.remove('open');
                document.body.classList.remove('modal-open');
            };
            // Tab switching
            settingsModal.querySelectorAll('.tab-btn').forEach(btn => {
                btn.onclick = function() {
                    settingsModal.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    const tab = btn.getAttribute('data-tab');
                    settingsModal.querySelectorAll('.tab-panel').forEach(panel => {
                        if (panel.getAttribute('data-tab') === tab) {
                            panel.classList.add('active');
                        } else {
                            panel.classList.remove('active');
                        }
                    });
                };
            });
            // Close modal on Escape
            document.addEventListener('keydown', function escListener(e) {
                if (settingsModal.classList.contains('open') && e.key === 'Escape') {
                    settingsModal.classList.remove('open');
                    document.body.classList.remove('modal-open');
                    document.removeEventListener('keydown', escListener);
                }
            });
        });
    }

    // Add event listener for the password settings form
    const passwordSettingsForm = document.getElementById('password-manager-form');
    if (passwordSettingsForm) {
        passwordSettingsForm.addEventListener('submit', async (event) => {
            event.preventDefault();

            const formData = new FormData(passwordSettingsForm);
            try {
                const response = await fetch('/update-password-settings', {
                    method: 'POST',
                    body: formData
                });

                if (response.ok) {
                    alert('Password settings updated successfully!');
                } else {
                    alert('Failed to update password settings.');
                }
            } catch (error) {
                console.error('Error updating password settings:', error);
                alert('An error occurred while updating password settings.');
            }
        });
    }
});
