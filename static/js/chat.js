/* ── SKYLINE Real-time Chat ──────────────────────── */
(function () {
    'use strict';

    const ME = window.CHAT_ME || {};
    const ROOM = window.CHAT_ROOM || null;
    const TO_USER = window.CHAT_TO_USER || null;
    const TOKEN = window.CHAT_TOKEN || '';

    if (!ME.username) return;

    const _auth = { token: TOKEN, user: ME.username, role: ME.role || 'user' };

    /* Socket — auth sent via protocol auth object AND re-sent as 'auth' event */
    const socket = io({
        transports: ['websocket', 'polling'],
        auth: _auth,
    });

    socket.on('connect', () => {
        console.log('[Chat] Connected sid=', socket.id);
        /* Re-send auth immediately after connect as a belt-and-suspenders guarantee */
        socket.emit('auth', _auth);
        if (ROOM) {
            socket.emit('join_chat', { room_id: ROOM });
            socket.emit('get_online_status', { username: TO_USER });
        }
    });

    socket.on('connect_error', (err) => {
        console.error('[Chat] Connection error:', err.message, err);
    });

    socket.on('disconnect', (reason) => {
        console.warn('[Chat] Disconnected:', reason);
    });

    /* ── Online Status ────────────────────────────── */
    socket.on('online_status', (data) => {
        const dot = document.querySelector(`.online-dot[data-user="${data.username}"]`);
        if (dot) {
            dot.classList.toggle('online', data.online);
            dot.classList.toggle('offline', !data.online);
        }
        const statusText = document.getElementById('chat-status-text');
        if (statusText && data.username === TO_USER) {
            statusText.textContent = data.online ? 'Online' : 'Offline';
            statusText.className = data.online ? 'chat-status-online' : 'chat-status-offline';
        }
        const badge = document.querySelector(`.contact-item[data-user="${data.username}"] .contact-dot`);
        if (badge) {
            badge.classList.toggle('online', data.online);
        }
    });

    /* ── Incoming Message ─────────────────────────── */
    socket.on('new_message', (data) => {
        if (data.room_id !== ROOM) return;
        appendMessage(data, data.from_username === ME.username);
        hideTyping();
        scrollBottom();
        if (data.from_username !== ME.username) {
            socket.emit('mark_read', { room_id: ROOM });
        }
    });

    /* ── Notification badge for other conversations ─ */
    socket.on('message_notification', (data) => {
        if (data.room_id === ROOM) return;
        const contactItem = document.querySelector(`.contact-item[data-user="${data.from_username}"]`);
        if (contactItem) {
            let badge = contactItem.querySelector('.contact-unread');
            if (!badge) {
                badge = document.createElement('span');
                badge.className = 'contact-unread';
                contactItem.appendChild(badge);
            }
            badge.textContent = (parseInt(badge.textContent || '0') + 1).toString();
        }
        updateSidebarBadge(1);
    });

    function updateSidebarBadge(delta) {
        const sb = document.getElementById('chat-sidebar-badge');
        if (!sb) return;
        const cur = parseInt(sb.textContent || '0') + delta;
        sb.textContent = cur > 0 ? cur : '';
        sb.style.display = cur > 0 ? 'flex' : 'none';
    }

    /* ── Typing ───────────────────────────────────── */
    let typingTimer = null;
    const input = document.getElementById('chat-input');
    if (input) {
        input.addEventListener('input', () => {
            socket.emit('typing', { room_id: ROOM, to_user: TO_USER });
            clearTimeout(typingTimer);
            typingTimer = setTimeout(() => {
                socket.emit('stop_typing', { room_id: ROOM, to_user: TO_USER });
            }, 2000);
        });

        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });
    }

    socket.on('user_typing', (data) => {
        if (data.username !== ME.username) showTyping(data.username);
    });

    socket.on('user_stop_typing', () => hideTyping());

    function showTyping(username) {
        const el = document.getElementById('typing-indicator');
        if (el) {
            el.style.display = 'flex';
            const name = el.querySelector('.typing-name');
            if (name) name.textContent = username;
            scrollBottom();
        }
    }

    function hideTyping() {
        const el = document.getElementById('typing-indicator');
        if (el) el.style.display = 'none';
    }

    /* ── Send ─────────────────────────────────────── */
    const sendBtn = document.getElementById('chat-send-btn');
    if (sendBtn) sendBtn.addEventListener('click', sendMessage);

    function sendMessage() {
        const text = (input?.value || '').trim();
        if (!text || !ROOM) return;
        /* Include auth data in every send_message as the final fallback */
        socket.emit('send_message', {
            room_id:  ROOM,
            to_user:  TO_USER,
            message:  text,
            token:    TOKEN,
            user:     ME.username,
            role:     ME.role || 'user',
        });
        input.value = '';
        socket.emit('stop_typing', { room_id: ROOM, to_user: TO_USER });
    }

    /* ── Render Message ───────────────────────────── */
    function appendMessage(data, isMine) {
        const container = document.getElementById('chat-messages');
        if (!container) return;

        const roleColor = { admin: 'admin', superadmin: 'admin', reseller: 'reseller', user: 'user' }[data.from_role] || 'user';
        const initial = (data.from_username || 'U')[0].toUpperCase();

        const picUrl = isMine ? (ME.profile_pic_url || null) : (data.profile_pic_url || null);
        const avatarHtml = picUrl
            ? `<div class="msg-avatar-wrap"><img src="${picUrl}" alt="${initial}" class="msg-avatar profile-img-avatar" style="object-fit:cover;border-radius:50%;width:100%;height:100%;display:block;"></div>`
            : `<div class="msg-avatar-wrap"><div class="msg-avatar role-${roleColor}">${initial}</div></div>`;

        const wrap = document.createElement('div');
        wrap.className = `msg-wrap ${isMine ? 'mine' : 'theirs'}`;
        wrap.innerHTML = `
            ${avatarHtml}
            <div class="msg-body">
                ${!isMine ? `<div class="msg-meta"><span class="msg-name">${escHtml(data.from_username)}</span><span class="role-tag role-${roleColor}">${roleLabel(data.from_role)}</span></div>` : ''}
                <div class="msg-bubble">${escHtml(data.message)}</div>
                <div class="msg-time">${data.timestamp}</div>
            </div>
        `;
        container.appendChild(wrap);
    }

    function roleLabel(r) {
        return { superadmin: 'Admin', admin: 'Admin', reseller: 'Reseller', user: 'User' }[r] || r;
    }

    function escHtml(str) {
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\n/g, '<br>');
    }

    function scrollBottom() {
        const c = document.getElementById('chat-messages');
        if (c) c.scrollTop = c.scrollHeight;
    }

    scrollBottom();

    window.ChatApp = { sendMessage, socket };
})();
