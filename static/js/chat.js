/* ── SKYLINE Real-time Chat ──────────────────────── */
(function () {
    'use strict';

    const ME      = window.CHAT_ME      || {};
    const ROOM    = window.CHAT_ROOM    || null;
    const TO_USER = window.CHAT_TO_USER || null;

    if (!ME.username) return;

    /* ── Socket ───────────────────────────────────── */
    const socket = io({ transports: ['websocket', 'polling'] });

    socket.on('connect', () => {
        if (ROOM) {
            socket.emit('join_chat', { room_id: ROOM });
            socket.emit('get_online_status', { username: TO_USER });
        }
    });

    /* ── Online Status ────────────────────────────── */
    socket.on('online_status', (data) => {
        const dot = document.querySelector(`.contact-dot[data-user="${data.username}"]`);
        if (dot) {
            dot.classList.toggle('online',  data.online);
            dot.classList.toggle('offline', !data.online);
        }
        const statusEl = document.getElementById('chat-status-text');
        if (statusEl && data.username === TO_USER) {
            if (data.online) {
                statusEl.innerHTML = '<i class="fas fa-circle" style="font-size:7px;color:#22c55e;"></i> Online';
                statusEl.className = 'chat-status-online';
            } else {
                statusEl.innerHTML = '<i class="fas fa-circle" style="font-size:7px;"></i> Offline';
                statusEl.className = 'chat-status-offline';
            }
        }
    });

    /* ── Incoming Message ─────────────────────────── */
    socket.on('new_message', (data) => {
        if (data.room_id !== ROOM) return;

        const noMsgs = document.querySelector('.chat-no-msgs');
        if (noMsgs) noMsgs.remove();

        appendMessage(data, data.from_username === ME.username);
        hideTyping();
        scrollBottom();

        if (data.from_username !== ME.username) {
            socket.emit('mark_read', { room_id: ROOM });
        }

        const previewTarget = data.from_username === ME.username ? TO_USER : data.from_username;
        updateContactPreview(previewTarget, data.message, data.timestamp);
    });

    /* ── Notification for other conversations ──────── */
    socket.on('message_notification', (data) => {
        if (data.room_id === ROOM) return;

        const unreadEl = document.getElementById(`unread-${data.from_username}`);
        if (unreadEl) {
            const cur = parseInt(unreadEl.textContent || '0') + 1;
            unreadEl.textContent = cur;
            unreadEl.style.display = 'flex';
        }

        bumpSidebarBadge(1);
        updateContactPreview(data.from_username, data.message, data.timestamp);
    });

    function bumpSidebarBadge(delta) {
        const sb = document.getElementById('chat-sidebar-badge');
        if (!sb) return;
        const cur = parseInt(sb.textContent || '0') + delta;
        sb.textContent = cur > 0 ? (cur > 99 ? '99+' : cur) : '';
        sb.style.display = cur > 0 ? 'flex' : 'none';
    }

    function updateContactPreview(contactUsername, text, ts) {
        const item = document.querySelector(`.contact-item[data-user="${contactUsername}"]`);
        if (!item) return;
        const preview = item.querySelector('.contact-preview');
        if (preview) {
            preview.textContent = text.length > 40 ? text.slice(0, 40) + '…' : text;
            preview.style.color = '';
        }
        const timeEl = item.querySelector('.contact-time');
        if (timeEl && ts) {
            timeEl.textContent = (typeof ts === 'string' && ts.length === 5) ? ts : (ts.slice ? ts.slice(11,16) : '');
        }
    }

    /* ── Typing ───────────────────────────────────── */
    let typingTimer = null;
    const input = document.getElementById('chat-input');

    if (input) {
        input.addEventListener('input', () => {
            if (!ROOM) return;
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
        if (!el) return;
        el.style.display = 'flex';
        const name = el.querySelector('#typing-name');
        if (name) name.textContent = username;
        scrollBottom();
    }
    function hideTyping() {
        const el = document.getElementById('typing-indicator');
        if (el) el.style.display = 'none';
    }

    /* ── Send ─────────────────────────────────────── */
    const sendBtn = document.getElementById('chat-send-btn');
    if (sendBtn) sendBtn.addEventListener('click', sendMessage);

    function sendMessage() {
        const text = (input ? input.value : '').trim();
        if (!text || !ROOM) return;
        socket.emit('send_message', { room_id: ROOM, to_user: TO_USER, message: text });
        input.value = '';
        clearTimeout(typingTimer);
        socket.emit('stop_typing', { room_id: ROOM, to_user: TO_USER });
        if (sendBtn) {
            sendBtn.style.transform = 'scale(0.88)';
            setTimeout(() => { sendBtn.style.transform = ''; }, 140);
        }
    }

    /* ── Render a Message ─────────────────────────── */
    function appendMessage(data, isMine) {
        const container = document.getElementById('chat-messages');
        if (!container) return;

        const roleColor = { admin:'admin', superadmin:'admin', reseller:'reseller', user:'user' }[data.from_role] || 'user';
        const initial   = (data.from_username || 'U')[0].toUpperCase();
        const time      = (typeof data.timestamp === 'string' && data.timestamp.length === 5)
            ? data.timestamp
            : (data.timestamp_full ? data.timestamp_full.slice(11, 16) : '');

        const wrap = document.createElement('div');
        wrap.className = `msg-wrap ${isMine ? 'mine' : 'theirs'}`;
        wrap.innerHTML = `
            <div class="msg-avatar role-${roleColor}">${initial}</div>
            <div class="msg-body">
                ${!isMine
                    ? `<div class="msg-meta">
                           <span class="msg-name">${escHtml(data.from_username)}</span>
                           <span class="role-tag role-${roleColor}">${roleLabel(data.from_role)}</span>
                       </div>`
                    : ''}
                <div class="msg-bubble">${escHtml(data.message)}</div>
                <div class="msg-time">${time}</div>
            </div>
        `;
        container.appendChild(wrap);
    }

    function roleLabel(r) {
        return { superadmin:'Admin', admin:'Admin', reseller:'Reseller', user:'User' }[r] || String(r||'');
    }

    function escHtml(str) {
        return (str || '')
            .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\n/g,'<br>');
    }

    function scrollBottom() {
        const c = document.getElementById('chat-messages');
        if (c) c.scrollTop = c.scrollHeight;
    }

    scrollBottom();
    window.ChatApp = { sendMessage, socket };
})();
