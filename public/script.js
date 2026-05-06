const socket = (typeof io !== 'undefined') ? io({ withCredentials: true }) : null;
const alertSound = new Audio('https://assets.mixkit.co/active_storage/sfx/2358/2358-preview.mp3');

function getCookie(name) {
    const needle = `${encodeURIComponent(name)}=`;
    const parts = String(document.cookie || '').split(';');
    for (const p of parts) {
        const s = p.trim();
        if (!s) continue;
        if (s.startsWith(needle)) return decodeURIComponent(s.slice(needle.length));
    }
    return '';
}

async function secureFetch(url, options = {}) {
    const method = String(options.method || 'GET').toUpperCase();
    const headers = new Headers(options.headers || {});
    const needsCsrf = method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';
    if (needsCsrf && !headers.has('X-CSRF-Token')) {
        const csrf = getCookie('csrfToken');
        if (csrf) headers.set('X-CSRF-Token', csrf);
    }
    // أغلب endpoints تعتمد على الكوكي HttpOnly للجلسة
    const credentials = options.credentials || 'include';
    return fetch(url, { ...options, method, headers, credentials });
}

/** دقة أعلى لأعلام الغرف الوطنية (أوضح من w80) */
const FLAG_CDN = 'https://flagcdn.com/w320';
const REGION_FLAGS = {
    GULF: ['sa', 'ae', 'kw', 'bh', 'qa', 'om'],
    NORTH_AFRICA: ['ma', 'mr', 'dz', 'tn', 'ly', 'eg'],
    LEVANT: ['sy', 'lb', 'ps', 'jo']
};

let userColor = '#' + Math.floor(Math.random() * 16777215).toString(16);
let currentRoom = '';
/** حالة الغرفة قبل محاولة الدخول (للاسترجاع عند رفض السيرفر مثل غرفة البنات) */
let joinDeniedRecovery = null;
let typingTimeout;
let currentPrivatePeer = null;
/** @type {Map<string, { messages: Array<{from:string,to:string,text?:string,media?:string,type:string,time:string,outgoing?:boolean}>, unread: number }>} */
const privateThreads = new Map();
const privateSeenAcked = new Set(); // messageId already sent to server
/** أسماء المستخدمين → آخر صورة رمزية وغلاف معروفان (قائمة المتصلين / رسائل خاصة) */
const peerProfileCache = new Map();
/** @type {Array<{text:string,time:string,read:boolean}>} */
const notifications = [];
let guestNoticePushed = false;
let contextTargetUser = '';
let moderationTargetUser = '';

function openModal(el) {
    if (!el) return;
    el.classList.remove('is-hidden');
    el.style.removeProperty('display');
}

function closeModalEl(el) {
    if (!el) return;
    el.classList.add('is-hidden');
    el.style.removeProperty('display');
}

function encryptData(data) {
    if (!data) return '';
    try {
        return btoa(encodeURIComponent(data));
    } catch (e) {
        return data;
    }
}

function decryptData(encryptedData) {
    if (!encryptedData) return '';
    try {
        return decodeURIComponent(atob(encryptedData));
    } catch (e) {
        return encryptedData;
    }
}

function setSecureItem(key, value) {
    if (value !== undefined && value !== null && value !== '') {
        localStorage.setItem(key, encryptData(String(value)));
    }
}

function getSecureItem(key) {
    const encrypted = localStorage.getItem(key);
    return encrypted ? decryptData(encrypted) : null;
}

function isGuestUser() {
    const t = getSecureItem('authType');
    if (!t) return true;
    return t !== 'member';
}

function sanitizeInput(input) {
    if (!input) return '';
    if (typeof DOMPurify !== 'undefined') {
        return DOMPurify.sanitize(input, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
    }
    return input.replace(/[<>{}`$]/g, '').trim();
}

/** Hue 0–359 for colored avatar badges (Messenger-style) */
function avatarHueFromString(str) {
    if (!str) return 200;
    let h = 0;
    for (let i = 0; i < str.length; i++) h = str.charCodeAt(i) + ((h << 5) - h);
    return Math.abs(h) % 360;
}

let emojiTargetMode = 'room';

function insertAtCursor(input, text) {
    if (!input || typeof text !== 'string') return;
    const start = input.selectionStart ?? input.value.length;
    const end = input.selectionEnd ?? start;
    const v = input.value;
    input.value = v.slice(0, start) + text + v.slice(end);
    const pos = start + text.length;
    try {
        input.setSelectionRange(pos, pos);
    } catch (_) {
        /* ignore */
    }
    input.focus();
}

function splitGraphemes(str) {
    if (typeof str !== 'string' || !str) return [];
    try {
        if (typeof Intl !== 'undefined' && Intl.Segmenter) {
            const seg = new Intl.Segmenter('en', { granularity: 'grapheme' });
            return [...seg.segment(str)].map((p) => p.segment);
        }
    } catch (_) {
        /* ignore */
    }
    return Array.from(str);
}

/* 0 وجوه (وسط الصف العلوي)، 6–7 يسار الوجه، 8–9 يمين الوجه؛ 1–2 يسار الكرة، 5 الكرة، 3–4 يمينها */
const EMOJI_CATEGORIES = [
    {
        tab: '😀',
        items: splitGraphemes(
            '😀😃😄😁😅🤣😂🙂🙃😉😊😇🥰😍🤩😘😗☺️😚😙🥲😋😜🤪😝🤑🤗🤭🤫🤔🤐🤨😐😑😶😏😒🙄😬🤥😌😔😪🤤😴😷🤒🤕🤢🤮🥵🥶🥴😵🤯🤠🥳🥸😎🤓🧐😕😟🙁☹️😮😯😲🥺😦😧😨😰😥😢😭😱😖😣😞😓😩😫🥱😤😡😠🤬😈👿💀☠️💩🤡👹👺👻👽👾🤖🎃😺😸😹😻😼😽🙀😿😾'
        )
    },
    {
        tab: '🐱',
        items: splitGraphemes(
            '🐶🐱🐭🐹🐰🦊🐻🐼🐨🐯🦁🐮🐷🐸🐵🙈🙉🙊🐒🐔🐧🐦🐤🦆🦅🦉🦇🐺🐗🐴🦄🐝🐛🦋🐌🐞🐜🦟🦗🕷️🦂🐢🐍🦎🐙🦑🦐🦞🦀🐡🐠🐟🐬🐳🐋🦈🐊🐅🐆🦓🦍🦧🐘🦛🦏🐪🐫🦒🦘🐃🐂🐄🐎🐖🐏🐑🐐🦌🐕🐩🐈🐇🦝🐿️🦔'
        )
    },
    {
        tab: '🍕',
        items: splitGraphemes(
            '🍏🍎🍐🍊🍋🍌🍉🍇🍓🍈🍒🍑🥭🍍🥥🥝🍅🍆🥑🥦🥬🥒🌶️🌽🥕🧄🧅🥔🍠🥐🥯🍞🥖🥨🧀🥚🍳🧈🥞🥓🥩🍗🍖🌭🍔🍟🍕🥪🌮🌯🥗🥘🍝🍜🍲🍛🍣🍱🍙🍚🍘🍥🥟🦪🍤🍡🍧🍨🍦🥧🧁🍰🎂🍮🍭🍬🍫🍩🍪🌰🥜🍯🥛☕🍵🧃🥤🍶🍺🍻🥂🍷🥃🍸🍹'
        )
    },
    {
        tab: '❤️',
        items: splitGraphemes(
            '❤️🧡💛💚💙💜🤎🖤🤍💔❣️💕💞💓💗💖💘💝💟✨⭐🌟💫⚡🔥💯✅❌❓❗💬💭🗯️♥️💋👑🎀🎁🎉🎊🏆🥇🥈🥉'
        )
    },
    {
        tab: '👋',
        items: splitGraphemes(
            '👋🤚🖐️✋🖖👌🤌🤏✌️🤞🫰🤟🤘🤙👈👉👆🖕👇☝️🫵👍👎✊👊🤛🤜👏🙌👐🤲🤝🙏✍️💅🤳💪🦾🦿🦵🦶👂🦻👃🧠🫀🫁🦷🦴👀👁️👅👄'
        )
    },
    {
        tab: '⚽',
        items: splitGraphemes(
            '⚽🏀🏈⚾🥎🎾🏐🏉🥏🎱🏓🏸🏒🏑🥍🏏🥅⛳🪁🏹🎣🥊🥋🎽🛹🛼🎿⛷🏂🧗🚴🚵🎮🎲🎯🎪🎨🎭🎬🎤🎧🎸🎹🥁🎺🎻🪕📱💻⌚📷📚✏️📌📎🔒🔑🏠🚗✈️🚀🌙☀️🌈☁️⛈️❄️🌊🌴🌷🌹🌻🍀'
        )
    },
    {
        tab: '🌍',
        items: splitGraphemes(
            '🌙☀️🌟✨🌈☁️⛅🌤️⛈️🌩️⚡🔥💧🌊🌀🌪️🌫️❄️☃️⛄🌨️🌬️🌡️☂️☔🌂🌁🌍🌎🌏🗺️🏔️⛰️🌋🗻🏕️🏖️🏜️🏝️🌴🌲🌳🌵🌾🌿☘️🍀🍁🍂🍃🪨🪵🦫🦦'
        )
    },
    {
        tab: '🎌',
        items: splitGraphemes(
            '🇸🇦🇪🇬🇲🇦🇩🇿🇹🇳🇱🇧🇵🇸🇦🇪🇶🇦🇧🇭🇰🇼🇴🇲🇾🇪🇮🇶🇸🇾🇯🇴🇺🇸🇬🇧🇫🇷🇩🇪🇮🇹🇪🇸🇧🇷🇯🇵🇰🇷🇨🇳🇹🇷🇷🇺🇮🇳🇨🇦🇦🇺🇳🇬🇰🇪🇿🇦🇦🇷🇲🇽🇮🇩🇵🇭🇻🇳🇬🇷🇳🇱🇸🇪🇳🇴🇩🇰🇫🇮🇵🇱🇨🇿🇭🇺🇷🇴🇧🇪🇨🇭🇦🇹🇵🇹🇬🇪🇦🇲🇦🇿🇺🇦🇮🇱🇮🇷🇵🇰🇧🇩'
        )
    },
    {
        tab: '🎵',
        items: splitGraphemes(
            '🎵🎶🎼🎹🥁🪘🎷🎺🪗🎸🪕🎻🎤🎧📻🔊🔉🔈📢📣🎚️🎛️🎙️🪩💿📀📼🎬🎭🖤🤍'
        )
    },
    {
        tab: '📎',
        items: splitGraphemes(
            '📎📌📍✂️🖇️📏📐✏️✒️🖊️🖋️📝💼📁📂🗂️📅📆🗓️📇📈📉📊📋📑📙📚📓📔📒📕📗📘📖🔖🏷️💰💴💵💶💷💳🧾✉️📧📨📩📤📥📦📫📪📬📭📮🗳️🧮🔍🔎🔑🗝️🔒🔓🔐🔏🛠️🔧🔨⚒️🪓⛏️⚙️🪛🔩🧲🪜'
        )
    }
];

const EMOJI_TOP_LEFT_IDX = [6, 7];
const EMOJI_TOP_RIGHT_IDX = [8, 9];
const EMOJI_HUB_LEFT_IDX = [1, 2];
const EMOJI_HUB_CENTER_IDX = 5;
const EMOJI_HUB_RIGHT_IDX = [3, 4];

function makeEmojiTabButton(catIndex, extraClass) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `emoji-pop-tab${extraClass ? ` ${extraClass}` : ''}`;
    btn.setAttribute('role', 'tab');
    btn.setAttribute('aria-selected', catIndex === 0 ? 'true' : 'false');
    btn.dataset.catIndex = String(catIndex);
    btn.textContent = EMOJI_CATEGORIES[catIndex].tab;
    return btn;
}

let emojiPopoverBuilt = false;

function setActiveEmojiTab(activeIdx) {
    document.querySelectorAll('#emojiPopoverTabsWrap .emoji-pop-tab').forEach((btn) => {
        const idx = parseInt(btn.dataset.catIndex, 10);
        const on = idx === activeIdx;
        btn.classList.toggle('is-active', on);
        btn.setAttribute('aria-selected', on ? 'true' : 'false');
    });
}

function renderEmojiCategory(index) {
    const scroll = document.getElementById('emojiPopoverScroll');
    if (!scroll || !EMOJI_CATEGORIES[index]) return;
    scroll.innerHTML = '';
    const grid = document.createElement('div');
    grid.className = 'emoji-popover-grid';
    EMOJI_CATEGORIES[index].items.forEach((emoji) => {
        const c = document.createElement('button');
        c.type = 'button';
        c.className = 'emoji-cell';
        c.dataset.emoji = emoji;
        c.textContent = emoji;
        c.setAttribute('aria-label', emoji);
        grid.appendChild(c);
    });
    scroll.appendChild(grid);
}

function ensureEmojiPopoverBuilt() {
    if (emojiPopoverBuilt) return;
    const facesRow = document.getElementById('emojiPopoverTabFaces');
    const hubRow = document.getElementById('emojiPopoverTabsHub');
    const scroll = document.getElementById('emojiPopoverScroll');
    if (!facesRow || !hubRow || !scroll) return;
    emojiPopoverBuilt = true;

    const topLeft = document.createElement('div');
    topLeft.className = 'emoji-pop-hub-group';
    EMOJI_TOP_LEFT_IDX.forEach((idx) => topLeft.appendChild(makeEmojiTabButton(idx, '')));

    const faceBtn = makeEmojiTabButton(0, 'is-active emoji-pop-tab--top-center');

    const topRight = document.createElement('div');
    topRight.className = 'emoji-pop-hub-group';
    EMOJI_TOP_RIGHT_IDX.forEach((idx) => topRight.appendChild(makeEmojiTabButton(idx, '')));

    facesRow.appendChild(topLeft);
    facesRow.appendChild(faceBtn);
    facesRow.appendChild(topRight);

    const leftGroup = document.createElement('div');
    leftGroup.className = 'emoji-pop-hub-group';
    EMOJI_HUB_LEFT_IDX.forEach((idx) => leftGroup.appendChild(makeEmojiTabButton(idx, '')));

    const centerBtn = makeEmojiTabButton(EMOJI_HUB_CENTER_IDX, 'emoji-pop-tab--center');

    const rightGroup = document.createElement('div');
    rightGroup.className = 'emoji-pop-hub-group';
    EMOJI_HUB_RIGHT_IDX.forEach((idx) => rightGroup.appendChild(makeEmojiTabButton(idx, '')));

    hubRow.appendChild(leftGroup);
    hubRow.appendChild(centerBtn);
    hubRow.appendChild(rightGroup);

    renderEmojiCategory(0);
    const tabsWrap = document.getElementById('emojiPopoverTabsWrap');
    tabsWrap?.addEventListener('click', (e) => {
        const b = e.target.closest('.emoji-pop-tab');
        if (!b || !tabsWrap.contains(b)) return;
        const idx = parseInt(b.dataset.catIndex, 10);
        if (Number.isNaN(idx)) return;
        setActiveEmojiTab(idx);
        renderEmojiCategory(idx);
    });
    scroll.addEventListener('click', (e) => {
        const cell = e.target.closest('.emoji-cell');
        if (!cell || !scroll.contains(cell)) return;
        const ch = cell.dataset.emoji;
        if (!ch) return;
        const input =
            emojiTargetMode === 'private'
                ? document.getElementById('privateMsgInput')
                : document.getElementById('msgInput');
        insertAtCursor(input, ch);
        hideEmojiPicker();
    });
}

function hideEmojiPicker() {
    const p = document.getElementById('emojiPopover');
    if (p) p.classList.add('is-hidden');
}

function toggleEmojiPicker(ev, mode) {
    if (ev) ev.stopPropagation();
    hideGifPicker();
    const pop = document.getElementById('emojiPopover');
    const anchor = mode === 'private' ? document.getElementById('emojiBtnPrivate') : document.getElementById('emojiBtnRoom');
    if (!pop || !anchor) return;
    if (!pop.classList.contains('is-hidden')) {
        hideEmojiPicker();
        return;
    }
    emojiTargetMode = mode;
    ensureEmojiPopoverBuilt();
    const pw = Math.min(288, window.innerWidth - 24);
    const rect = anchor.getBoundingClientRect();
    let left = rect.left + rect.width / 2 - pw / 2;
    left = Math.min(Math.max(12, left), window.innerWidth - pw - 12);
    const estH = 300;
    let top = rect.bottom + 8;
    if (top + estH > window.innerHeight - 12) {
        top = Math.max(12, rect.top - estH - 8);
    }
    pop.style.left = `${left}px`;
    pop.style.top = `${top}px`;
    pop.classList.remove('is-hidden');
}

let gifTargetMode = 'room';
let gifPopoverUiReady = false;
let gifSearchTimer = null;

/** احتياط إذا تعذّر الاتصال بـ /api/gifs — يجب أن يطابق DEFAULT_GIF_IDS في server.js */
const GIF_STICKER_FALLBACK_IDS = [
    'l0MYC0LajqoPoEADC', 'g9582DNuQppxC', 'ICOgUNjpvO0PC', '26ufdipQqU2lhNA4g', '3o7abKhOpu0NwenH3O',
    'xTiTnqUxyBBSQU2Sj6', 'l0HlNQ03J5JxX6lva', '26BRvOYThfA6CdTNQ', '3o7aD2saalBwwftBIY',
    'MoWy9eEFSfMSJDBOlC', '13CoXDjaCcik0g', '5GoVLqeAOo6PK', 'l3q2K5jinAlChoCLS',
    '3oz8xIsdbV8OB3MOcM', 'yJFeycNHJxZjhutfP8', '3o7bu3XilJ5BOiSGQ', '3o7TKSjRrfIPjeiM2A',
    'xT9IgG50Fb7Mi0prBC', 'xT4uQulxzU39HRPb6o', '3ornka9rIrKbleeWdO', 'l1J9EdzfOSgfyueLm',
    '3oEjI6SIIHBdVxXI1y', '10UUe8ZkL9kWjKICDs', 'l0MYK5fxmPYssagfK', 'gV1oRSJURBXQA',
    '3oKIPkKyhmUWuvdSpO', 'LmNwrBhejkK9EFZi5UC', 'KDOutU5alkEjYI1OhJ', '4LTBas36MaNihEoUO6',
    'Zw3oBUuOlDJaHspPQG', 'd3mlE7uhX8KFgEmY', '8TweEdaxOcuqQ6Up3C', 'ceHKRKRP6deFiKGpZL',
    'WwCdWnuvYrKXHxjEr4', 'LOEt9F2SajxuAhXTQh', '1NKtnZo5HZ6C9A7SZy', '9J7tdYltWyXIhGX80I',
    'SqMKZGY1Lf7mo', 'mGK0gKMZU9200', 'o0vwzuFwCGAFO', 'AGskxwVyGTtZS'
];

function giphyIGifClient(id) {
    return `https://i.giphy.com/${id}.gif`;
}

function curatedGifEntries() {
    return GIF_STICKER_FALLBACK_IDS.map((id) => {
        const u = giphyIGifClient(id);
        return { id, thumb: u, url: u };
    });
}

function attachGifPreview(img, thumb, url, id) {
    if (!img || !url) return;
    const tries = [];
    const add = (u) => {
        if (u && !tries.includes(u)) tries.push(u);
    };
    add(thumb);
    add(url);
    if (id) {
        add(giphyIGifClient(id));
        add(`https://media.giphy.com/media/${id}/giphy.gif`);
    }
    let step = 0;
    img.onerror = () => {
        step += 1;
        if (step < tries.length) img.src = tries[step];
        else {
            img.onerror = null;
            img.style.opacity = '0.35';
        }
    };
    img.src = tries[0] || url;
}

function hideGifPicker() {
    const p = document.getElementById('gifPopover');
    if (p) p.classList.add('is-hidden');
}

function initGifPopoverUiOnce() {
    if (gifPopoverUiReady) return;
    const scroll = document.getElementById('gifPopoverScroll');
    if (!scroll) return;
    gifPopoverUiReady = true;
    scroll.innerHTML = '';
    const toolbar = document.createElement('div');
    toolbar.className = 'gif-popover-toolbar';
    const inp = document.createElement('input');
    inp.type = 'search';
    inp.id = 'gifSearchInput';
    inp.className = 'gif-popover-search';
    inp.autocomplete = 'off';
    inp.maxLength = 100;
    inp.setAttribute('data-i18n-placeholder', 'phGifSearch');
    inp.placeholder = tKey('phGifSearch') || 'Search GIFs...';
    toolbar.appendChild(inp);
    const grid = document.createElement('div');
    grid.className = 'gif-popover-grid';
    grid.id = 'gifPopoverGrid';
    scroll.appendChild(toolbar);
    scroll.appendChild(grid);
    scroll.addEventListener('click', (e) => {
        const cell = e.target.closest('.gif-picker-cell');
        if (!cell || !grid.contains(cell)) return;
        const u = cell.dataset.gifUrl;
        if (u) sendGifSticker(u);
    });
    inp.addEventListener('input', () => {
        clearTimeout(gifSearchTimer);
        gifSearchTimer = setTimeout(() => loadGifsFromApi(inp.value.trim()), 380);
    });
    inp.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter') return;
        e.preventDefault();
        clearTimeout(gifSearchTimer);
        loadGifsFromApi(inp.value.trim());
    });
}

async function loadGifsFromApi(query) {
    const grid = document.getElementById('gifPopoverGrid');
    if (!grid) return;
    grid.innerHTML = '';
    const loading = document.createElement('div');
    loading.className = 'gif-popover-loading';
    loading.textContent = '…';
    grid.appendChild(loading);
    const limit = 40;
    let items = [];
    try {
        const qs = new URLSearchParams({ limit: String(limit) });
        if (query) qs.set('q', query);
        const r = await fetch(`/api/gifs?${qs}`);
        const j = await r.json();
        if (Array.isArray(j.gifs)) items = j.gifs;
    } catch (_) {
        items = [];
    }
    if (!items.length) items = curatedGifEntries();
    grid.innerHTML = '';
    items.forEach((entry) => {
        const url = entry && entry.url;
        const thumb = (entry && entry.thumb) || url;
        if (!url) return;
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'gif-picker-cell';
        b.dataset.gifUrl = url;
        if (entry && entry.id) b.dataset.gifId = entry.id;
        const img = document.createElement('img');
        img.alt = '';
        img.loading = 'lazy';
        attachGifPreview(img, thumb, url, entry && entry.id);
        b.appendChild(img);
        grid.appendChild(b);
    });
}

function ensureGifPopoverBuilt() {
    initGifPopoverUiOnce();
}

function toggleGifPicker(ev, mode) {
    if (ev) ev.stopPropagation();
    hideEmojiPicker();
    const pop = document.getElementById('gifPopover');
    const anchor = mode === 'private' ? document.getElementById('gifBtnPrivate') : document.getElementById('gifBtnRoom');
    if (!pop || !anchor) return;
    if (!pop.classList.contains('is-hidden')) {
        hideGifPicker();
        return;
    }
    gifTargetMode = mode;
    ensureGifPopoverBuilt();
    const searchInp = document.getElementById('gifSearchInput');
    loadGifsFromApi(searchInp && searchInp.value ? searchInp.value.trim() : '');
    const pw = 292;
    const rect = anchor.getBoundingClientRect();
    let left = rect.left + rect.width / 2 - pw / 2;
    left = Math.min(Math.max(12, left), window.innerWidth - pw - 12);
    const estH = 360;
    let top = rect.bottom + 8;
    if (top + estH > window.innerHeight - 12) {
        top = Math.max(12, rect.top - estH - 8);
    }
    pop.style.left = `${left}px`;
    pop.style.top = `${top}px`;
    pop.classList.remove('is-hidden');
}

function sendGifSticker(url) {
    if (!url) return;
    if (gifTargetMode === 'room') {
        if (isGuestUser()) {
            addNotification('عفواً لا يمكنك المشاركة العامة، يجب تسجيل حساب أولاً حتي تتمكن من المشاركة في المحادثه الجماعية العامة، انتا الآن زائر بإمكانك استخدام الدردشة الخاصة فقط.!');
            return;
        }
        if (!socket || !currentRoom) return;
        socket.emit('chatMessage', {
            room: currentRoom,
            username: getSecureItem('nickname') || 'Guest',
            text: '',
            type: 'gif',
            media: url,
            color: userColor,
            time: getCurrentTime()
        });
    } else {
        if (!socket || !currentPrivatePeer) return;
        socket.emit('privateMessage', {
            toUsername: currentPrivatePeer,
            text: '',
            type: 'gif',
            media: url,
            color: userColor
        });
    }
    hideGifPicker();
}

function filterSidebarUsers() {
    const inp = document.getElementById('sidebarUserSearch');
    const q = (inp?.value || '').trim().toLowerCase();
    document.querySelectorAll('#sidebarUserList .sidebar-user-row').forEach((row) => {
        const nameEl = row.querySelector('.sidebar-user-name');
        const name = (nameEl?.textContent || '').toLowerCase();
        row.style.display = !q || name.includes(q) ? '' : 'none';
    });
}

function sanitizeNickname(nickname) {
    if (!nickname) return '';
    let cleaned = nickname.replace(/[^a-zA-Z0-9\u0600-\u06FF\s_]/g, '');
    cleaned = cleaned.trim();
    if (cleaned.length > 20) cleaned = cleaned.substring(0, 20);
    return cleaned || 'Guest';
}

function isValidImage(file) {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!allowedTypes.includes(file.type)) return false;
    const ext = file.name.split('.').pop().toLowerCase();
    return ['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(ext);
}

/** تقليل حجم الصور قبل الإرسال (JPEG) — يحافظ على GIF كما هي */
function compressImageFileToDataUrl(file, opts = {}) {
    const maxDim = opts.maxDim != null ? opts.maxDim : 1280;
    const maxBytes = opts.maxBytes != null ? opts.maxBytes : 1.75 * 1024 * 1024;
    if (!file || !file.type || file.type === 'image/gif') {
        return new Promise((resolve, reject) => {
            const r = new FileReader();
            r.onload = () => resolve(r.result);
            r.onerror = () => reject(new Error('read'));
            r.readAsDataURL(file);
        });
    }
    return new Promise((resolve, reject) => {
        const url = URL.createObjectURL(file);
        const img = new Image();
        img.onload = () => {
            URL.revokeObjectURL(url);
            let w = img.naturalWidth || img.width;
            let h = img.naturalHeight || img.height;
            if (!w || !h) {
                reject(new Error('dims'));
                return;
            }
            const scale = Math.min(1, maxDim / Math.max(w, h));
            w = Math.round(w * scale);
            h = Math.round(h * scale);
            const canvas = document.createElement('canvas');
            canvas.width = w;
            canvas.height = h;
            const ctx = canvas.getContext('2d');
            if (!ctx) {
                reject(new Error('ctx'));
                return;
            }
            ctx.drawImage(img, 0, 0, w, h);
            let q = 0.82;
            let dataUrl = canvas.toDataURL('image/jpeg', q);
            while ((dataUrl.length * 3) / 4 > maxBytes && q > 0.42) {
                q -= 0.07;
                dataUrl = canvas.toDataURL('image/jpeg', q);
            }
            resolve(dataUrl);
        };
        img.onerror = () => {
            URL.revokeObjectURL(url);
            reject(new Error('load'));
        };
        img.src = url;
    });
}

const translations = {
    ar: {
        title: 'دردشة عشوائية',
        subtitle: 'تحدث مع غرباء بخصوصية تامة. بدون تسجيل.',
        google: 'الدخول بجوجل',
        guest: 'الدخول كضيف',
        register: 'إنشاء حساب',
        member: 'تسجيل الدخول',
        registerTitle: '✨ إنشاء حساب',
        nickLabel: 'أدخل اسمك المستعار',
        settings: 'الإعدادات',
        profile: 'ملفي الشخصي',
        roomsList: 'قائمة الغرف',
        logout: 'تسجيل الخروج',
        logoutAllDevices: 'تسجيل الخروج من كل الأجهزة',
        emailNotVerified: 'يرجى تأكيد البريد الإلكتروني قبل تسجيل الدخول.',
        sessionRevoked: 'انتهت الجلسة. سجّل الدخول مجدداً.',
        chooseRoom: '🌍 اختر غرفة للدردشة',
        welcome: 'مرحباً بعودتك، ',
        general: 'عام',
        islamiyat: 'إسلاميات',
        morocco: 'المغرب',
        saudi: 'السعودية',
        egypt: 'مصر',
        palestine: 'فلسطين',
        lebanon: 'لبنان',
        algeria: 'الجزائر',
        tunisia: 'تونس',
        bahrain: 'البحرين',
        qatar: 'قطر',
        uae: 'الإمارات',
        syria: 'سوريا',
        gulf: 'الخليج',
        northAfrica: 'شمال أفريقيا',
        levant: 'الشام',
        profileTitle: '👤 الملف الشخصي',
        inboxTitle: 'محادثات خاصة',
        inboxEmpty: 'لا محادثات بعد',
        tabRoom: 'الغرفة',
        onlineUsersTitle: '👥 المتصلون',
        saveProfile: 'حفظ كل الإعدادات',
        typing: 'يكتب الآن...',
        noMessages: 'لا توجد رسائل',
        noMessagesDesc: 'رسائلك ستظهر هنا',
        tabBasic: 'المعلومات الأساسية',
        tabAccount: 'الحساب',
        tabPrivacy: 'الخصوصية',
        tabNotifications: 'الإشعارات',
        labelUsername: '👤 اسم المستخدم',
        labelGender: '⚥ الجنس',
        labelAge: '🎂 العمر',
        labelCountry: '🌍 الدولة',
        labelRelationship: '💑 الحالة الاجتماعية',
        labelBio: '💬 نبذة',
        labelEmail: '📧 البريد الإلكتروني',
        labelPassword: '🔐 كلمة المرور',
        labelChatLang: '🌐 لغة الدردشة',
        labelTimezone: '🕒 المنطقة الزمنية',
        hintEmail: '⚠️ تُرسل رسالة تفعيل الحساب إلى هذا البريد',
        hintPassword: '⚠️ استخدم كلمة مرور قوية لحماية حسابك',
        labelPrivacyImages: '📸 من يمكنه إرسال صور خاصة إلي؟',
        labelPrivateChat: '💬 الدردشة الخاصة',
        labelOnlineStatus: '👁️ إظهار حالة الاتصال',
        labelNotifSound: '🔊 المؤثرات الصوتية',
        labelNotifJoinLeave: '👋 رسائل الدخول والخروج',
        labelNotifTheme: '🎨 المظهر',
        phUsername: 'اسمك المستعار',
        phAge: 'مثال: 20',
        phBio: 'اكتب نبذة عنك...',
        phEmail: 'بريدك@example.com',
        phPassword: '••••••••',
        phMessage: 'اكتب رسالة...',
        phGifSearch: 'ابحث عن GIF...',
        avatarChange: 'تغيير الصورة',
        avatarHint: 'JPG أو PNG أو WebP — حتى 1 ميجابايت',
        coverChange: 'صورة الغلاف',
        coverHint: 'JPG أو PNG أو WebP — حتى 1.2 ميجابايت',
        onlineLabel: 'متصل',
        optMale: 'ذكر ♂',
        optFemale: 'أنثى ♀',
        optOther: 'آخر',
        relNotSpecified: 'غير محدد',
        relSingle: 'أعزب/عزباء',
        relMarried: 'متزوج/ة',
        relInRelationship: 'في علاقة',
        relComplicated: 'معقدة',
        privacyEveryone: 'الجميع',
        privacyFriends: 'الأصدقاء فقط',
        privacyNobody: 'لا أحد',
        privateChatOn: 'مفعّل',
        privateChatOff: 'معطّل',
        onlineShow: 'إظهار للجميع',
        onlineHide: 'إخفاء',
        notifAllSounds: 'كل الأصوات',
        notifMentions: 'عند الإشارة فقط',
        notifMute: 'كتم الكل',
        notifJoinShow: 'إظهار',
        notifJoinHide: 'إخفاء',
        themeDark: '🌙 داكن (افتراضي)',
        themeLight: '☀️ فاتح',
        themeGlass: '✨ زجاجي',
        langEn: 'الإنجليزية',
        langAr: 'العربية'
        ,
        notificationsTitle: 'الإشعارات',
        notificationsEmpty: 'لا توجد إشعارات',
        memberLoginTitle: 'دخول الأعضاء',
        memberUsernamePh: 'اسم المستخدم',
        memberPasswordPh: 'كلمة المرور',
        memberLoginBtn: 'دخول',
        memberInvalid: 'بيانات الدخول غير صحيحة',
        googleDisabled:
            'تسجيل الدخول بجوجل غير مُعدّ بعد. أضف GOOGLE_CLIENT_ID و GOOGLE_CLIENT_SECRET في إعدادات السيرفر.',
        oauthErr_cancelled: 'ألغيت نافذة جوجل. يمكنك المحاولة مرة أخرى.',
        oauthErr_token: 'فشل التحقق مع جوجل. حاول مرة أخرى لاحقاً.',
        oauthErr_profile: 'تعذّر قراءة بيانات الحساب من جوجل.',
        oauthErr_email_in_use: 'هذا البريد مسجّل مسبقاً كحساب عادي. سجّل الدخول بالاسم وكلمة المرور.',
        oauthErr_account_conflict: 'تعارض في الحساب. تواصل مع الدعم إن استمرّ الأمر.',
        oauthErr_banned_permanent: 'هذا الحساب محظور بشكل دائم.',
        oauthErr_banned_temp: 'هذا الحساب محظور مؤقتاً.',
        oauthErr_email_not_verified: 'يجب تأكيد البريد قبل الدخول.',
        oauthErr_server: 'خطأ في السيرفر أثناء تسجيل الدخول بجوجل.'
        ,
        ctxReport: 'إبلاغ',
        ctxBlock: 'حظر',
        reportTitle: '🚩 إبلاغ عن مستخدم',
        reportReason: 'سبب الإبلاغ',
        reportDetails: 'تفاصيل إضافية (اختياري)',
        submitReport: 'إرسال التبليغ',
        reportAgainst: 'الإبلاغ عن:',
        reportSentToast: 'تم إرسال التبليغ، شكراً لك',
        reasonHarassment: 'تحرش',
        reasonAbusiveLanguage: 'لفظ سيء',
        reasonExplicitImage: 'صورة خادشة',
        reasonSpam: 'إزعاج',
        reasonOther: 'سبب آخر',
        blockTitle: '⛔ حظر المستخدم',
        blockConfirmText: 'هل تريد حظر هذا المستخدم؟ لن يتمكن من مراسلتك أو الظهور في بحثك.',
        confirmBlock: 'تأكيد',
        cancel: 'إلغاء',
        cancel2: 'إلغاء',
        targetUser: 'المستخدم',
        blockedDone: 'تم حظر المستخدم.',
        ctxPrivate: 'محادثة خاصة',
        ctxProfile: 'عرض الملف الشخصي',
        privateChatsTitle: 'المحادثات',
        phThreadSearch: 'ابحث في المحادثات...',
        phSearchUsers: 'ابحث عن أسماء...',
        sidebarOnline: 'متصل',
        googleSoon: 'تسجيل الدخول بجوجل غير مفعّل بعد في هذا الإصدار.',
        randomFabShort: 'عشوائي',
        randomTopTooltip: 'دردشة عشوائية — فضفض / مطابقة',
        randomEarnPoints: 'ربح النقاط',
        randomModeVoice: 'صوت',
        randomModeText: 'كتابة',
        randomChatWith: 'تحدث مع:',
        randomMale: 'ذكر',
        randomFemale: 'أنثى',
        randomAll: 'الكل',
        randomFree: 'مجاناً',
        randomStart: 'فضفض',
        randomSearching: 'جاري البحث…',
        randomCancelSearch: 'إلغاء',
        randomSkip: 'تخطي',
        randomPointsTitle: 'النقاط والباقات',
        randomPointsSub: 'اختر خياراً',
        randomMonthly: 'باقة شهرية',
        randomBuyPoints: 'شراء نقاط',
        randomFreePts: 'نقاط مجانية (إعلان)',
        randomAdTitle: 'فيديو إعلاني',
        randomAdHint: 'شاهد للحصول على +5 💎',
        randomAdWait: 'انتظر…',
        randomAdDone: 'إغلاق',
        randomRegAll: '🌐 الكل',
        phRandomMsg: 'اكتب رسالة…',
        randomSoon: 'قريباً — الدفع غير مفعّل بعد',
        randomLowPoints: 'رصيد 💎 غير كافٍ',
        randomLowGender: 'يلزم 15 💎 لفلترة الجنس (ذكر/أنثى).',
        randomLowCountry: 'اشتراك شهري أو 5 💎 على الأقل لاختيار دولة محددة.',
        randomLowCombined: 'رصيد 💎 غير كافٍ لهذه الخيارات.',
        randomMonthlyActivated: 'تم تفعيل الباقة الشهرية لمدة 30 يوماً — اختيار الدولة بدون خصم.',
        joinRoomDeniedGirls: 'هذه الغرفة للبنات فقط. اضبط الجنس «أنثى» في الملف الشخصي للدخول.',
        roomGirls: 'غرفة البنات',
        randomNeedNick: 'أدخل اسماً من الصفحة الرئيسية أولاً',
        randomVoiceSoon: 'المحادثة الصوتية قريباً — استخدم الكتابة الآن',
        randomEndPartner: 'أنهى الطرف الآخر المحادثة',
        randomEndYou: 'تم إنهاء المحادثة'
    },
    en: {
        title: 'Random Chat',
        subtitle: 'Talk to strangers instantly. Private & Anonymous.',
        google: 'Login with Google',
        guest: 'Continue as Guest',
        register: 'Create Account',
        member: 'Login',
        registerTitle: '✨ Create Account',
        nickLabel: 'Enter Nickname',
        settings: 'Settings',
        profile: 'My Profile',
        roomsList: 'Rooms List',
        logout: 'Logout',
        logoutAllDevices: 'Log out of all devices',
        emailNotVerified: 'Please verify your email before signing in.',
        sessionRevoked: 'Your session ended. Please sign in again.',
        chooseRoom: '🌍 Choose a Room',
        welcome: 'Welcome back, ',
        general: 'General',
        islamiyat: 'Islamiyat',
        morocco: 'Morocco',
        saudi: 'Saudi Arabia',
        egypt: 'Egypt',
        palestine: 'Palestine',
        lebanon: 'Lebanon',
        algeria: 'Algeria',
        tunisia: 'Tunisia',
        bahrain: 'Bahrain',
        qatar: 'Qatar',
        uae: 'UAE',
        syria: 'Syria',
        gulf: 'Gulf',
        northAfrica: 'North Africa',
        levant: 'Levant',
        roomGirls: 'Girls only',
        profileTitle: '👤 My Profile',
        inboxTitle: 'Private conversations',
        inboxEmpty: 'No conversations yet',
        tabRoom: 'Room',
        onlineUsersTitle: '👥 Online Users',
        saveProfile: 'Save All Settings',
        typing: 'is typing...',
        noMessages: 'No messages yet',
        noMessagesDesc: 'Your messages will appear here',
        tabBasic: 'Basic Info',
        tabAccount: 'Account',
        tabPrivacy: 'Privacy',
        tabNotifications: 'Notifications',
        labelUsername: '👤 Username',
        labelGender: '⚥ Gender',
        labelAge: '🎂 Age',
        labelCountry: '🌍 Country',
        labelRelationship: '💑 Relationship',
        labelBio: '💬 Bio',
        labelEmail: '📧 Email',
        labelPassword: '🔐 Password',
        labelChatLang: '🌐 Chat Language',
        labelTimezone: '🕒 Timezone',
        hintEmail: '⚠️ Will receive account activation message',
        hintPassword: '⚠️ Use a strong password for account security',
        labelPrivacyImages: '📸 Who can send me private images?',
        labelPrivateChat: '💬 Private Chat',
        labelOnlineStatus: '👁️ Show my online status',
        labelNotifSound: '🔊 Sound Effects',
        labelNotifJoinLeave: '👋 Show join/leave messages',
        labelNotifTheme: '🎨 Theme',
        phUsername: 'Nickname',
        phAge: 'e.g. 20',
        phBio: 'Tell something about yourself...',
        phEmail: 'your@email.com',
        phPassword: '••••••••',
        phMessage: 'Type a message...',
        phGifSearch: 'Search GIFs...',
        avatarChange: 'Change photo',
        avatarHint: 'JPG, PNG or WebP — up to 1 MB',
        coverChange: 'Cover photo',
        coverHint: 'JPG, PNG or WebP — up to 1.2 MB',
        onlineLabel: 'Online',
        optMale: 'Male ♂',
        optFemale: 'Female ♀',
        optOther: 'Other',
        relNotSpecified: 'Not specified',
        relSingle: 'Single',
        relMarried: 'Married',
        relInRelationship: 'In a relationship',
        relComplicated: "It's complicated",
        privacyEveryone: 'Everyone',
        privacyFriends: 'Friends only',
        privacyNobody: 'Nobody',
        privateChatOn: 'Enabled',
        privateChatOff: 'Disabled',
        onlineShow: 'Show to everyone',
        onlineHide: 'Hide',
        notifAllSounds: 'All sounds',
        notifMentions: 'Mentions only',
        notifMute: 'Mute all',
        notifJoinShow: 'Show',
        notifJoinHide: 'Hide',
        themeDark: '🌙 Dark (Default)',
        themeLight: '☀️ Light',
        themeGlass: '✨ Glass',
        langEn: 'English',
        langAr: 'العربية'
        ,
        notificationsTitle: 'Notifications',
        notificationsEmpty: 'No notifications',
        memberLoginTitle: 'Member Login',
        memberUsernamePh: 'Username',
        memberPasswordPh: 'Password',
        memberLoginBtn: 'Login',
        memberInvalid: 'Invalid login credentials',
        googleDisabled:
            'Google sign-in is not configured yet. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET on the server.',
        oauthErr_cancelled: 'Google sign-in was cancelled. You can try again.',
        oauthErr_token: 'Google verification failed. Try again later.',
        oauthErr_profile: 'Could not read your Google profile.',
        oauthErr_email_in_use: 'This email is already registered with a password. Sign in with username and password.',
        oauthErr_account_conflict: 'Account conflict. Contact support if this persists.',
        oauthErr_banned_permanent: 'This account is permanently banned.',
        oauthErr_banned_temp: 'This account is temporarily banned.',
        oauthErr_email_not_verified: 'Email must be verified before sign-in.',
        oauthErr_server: 'Server error during Google sign-in.'
        ,
        ctxReport: 'Report',
        ctxBlock: 'Block',
        reportTitle: '🚩 Report User',
        reportReason: 'Report reason',
        reportDetails: 'Additional details (optional)',
        submitReport: 'Send Report',
        reportAgainst: 'Reporting:',
        reportSentToast: 'Report sent, thank you',
        reasonHarassment: 'Harassment',
        reasonAbusiveLanguage: 'Abusive language',
        reasonExplicitImage: 'Explicit image',
        reasonSpam: 'Spam / annoyance',
        reasonOther: 'Other',
        blockTitle: '⛔ Block user',
        blockConfirmText: 'Do you want to block this user? They will not be able to message you or appear in your search.',
        confirmBlock: 'Confirm',
        cancel: 'Cancel',
        cancel2: 'Cancel',
        targetUser: 'User',
        blockedDone: 'User blocked.',
        ctxPrivate: 'Private chat',
        ctxProfile: 'View profile',
        privateChatsTitle: 'Chats',
        phThreadSearch: 'Search conversations...',
        phSearchUsers: 'Search for people...',
        sidebarOnline: 'Online',
        googleSoon: 'Google sign-in is not enabled in this version yet.',
        randomFabShort: 'Random',
        randomTopTooltip: 'Random match chat',
        randomEarnPoints: 'Earn points',
        randomModeVoice: 'Voice',
        randomModeText: 'Text',
        randomChatWith: 'Chat with:',
        randomMale: 'Male',
        randomFemale: 'Female',
        randomAll: 'All',
        randomFree: 'Free',
        randomStart: 'Start',
        randomSearching: 'Searching…',
        randomCancelSearch: 'Cancel',
        randomSkip: 'Skip',
        randomPointsTitle: 'Points & packs',
        randomPointsSub: 'Pick an option',
        randomMonthly: 'Monthly pack',
        randomBuyPoints: 'Buy points',
        randomFreePts: 'Free points (watch ad)',
        randomAdTitle: 'Sponsored video',
        randomAdHint: 'Watch to earn +5 💎',
        randomAdWait: 'Please wait…',
        randomAdDone: 'Close',
        randomRegAll: '🌐 All',
        phRandomMsg: 'Message…',
        randomSoon: 'Coming soon — payments not wired yet',
        randomLowPoints: 'Not enough 💎',
        randomLowGender: '15 💎 required for gender filter (male/female).',
        randomLowCountry: 'Monthly plan or at least 5 💎 needed to pick a specific country.',
        randomLowCombined: 'Not enough 💎 for these options.',
        randomMonthlyActivated: 'Monthly plan active for 30 days — country choice has no extra cost.',
        joinRoomDeniedGirls: 'This room is for women only. Set gender to female in your profile to enter.',
        randomNeedNick: 'Set a nickname on the home page first',
        randomVoiceSoon: 'Voice chat coming soon — use text for now',
        randomEndPartner: 'The other person left',
        randomEndYou: 'Chat ended'
    }
};

const RANDOM_DIAMOND_KEY = 'randomMatchDiamonds';
const RANDOM_MONTHLY_UNTIL_KEY = 'randomMonthlyUntil';
const RANDOM_FILTER_COST = 15;
const RANDOM_COUNTRY_COST = 5;
const RANDOM_AD_REWARD = 5;
/** رموز ISO2 احتياطية إن لم يدعم المتصفح Intl.supportedValuesOf('region') */
const RANDOM_REGION_CODES_FALLBACK = 'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'.split(/\s+/);
let randomWantSelection = 'any';
let randomChatMode = 'text';
let randomLastPaidForFilter = false;
let randomLastPaidForCountry = false;
let randomAdProgressTimer = null;
let randomRegionPickerBound = false;
let randomAutoRestartWanted = false;
let randomBackToLobbyWanted = false;
let randomLastSearchPrefs = { want: 'any', region: 'all', mode: 'text' };
let randomToastTimer = null;

function showRandomToast(msg, ms = 3000) {
    const el = document.getElementById('randomToast');
    if (!el) return;
    if (randomToastTimer) {
        clearTimeout(randomToastTimer);
        randomToastTimer = null;
    }
    el.textContent = String(msg || '');
    el.classList.remove('is-hidden');
    // force reflow so transition always fires
    void el.offsetWidth;
    el.classList.add('is-show');
    randomToastTimer = setTimeout(() => {
        el.classList.remove('is-show');
        randomToastTimer = setTimeout(() => {
            el.classList.add('is-hidden');
        }, 260);
    }, ms);
}

function setRandomWantUI(want) {
    randomWantSelection = want;
    document.querySelectorAll('.random-gender-card').forEach((c) => {
        c.classList.toggle('random-gender-card--active', c.getAttribute('data-want') === want);
    });
}

function setRandomRegionValue(code) {
    const sel = document.getElementById('randomRegionSelect');
    if (sel) sel.value = String(code || 'all').toLowerCase();
    const menu = document.getElementById('randomRegionMenu');
    const btn = document.getElementById('randomRegionPickerBtn');
    const label = document.getElementById('randomRegionLabel');
    const flag = document.getElementById('randomRegionFlag');
    if (!menu || !btn || !label || !flag) return;
    const row = menu.querySelector(`.random-region-picker__item[data-code="${(sel?.value || 'all')}"]`);
    if (row) row.click();
}

function autoRestartRandomSearchIfPossible() {
    // لا نعيد البحث إلا إذا واجهة فضفض مفتوحة
    const app = document.getElementById('randomMatchApp');
    if (!app || app.classList.contains('is-hidden')) return;

    // حاول بنفس آخر تفضيلات؛ لو النقاط لا تكفي نُسقط الفلاتر تلقائياً
    let want = randomLastSearchPrefs.want || 'any';
    let region = (document.getElementById('randomRegionSelect')?.value || randomLastSearchPrefs.region || 'all').toLowerCase();

    // لو فلتر الجنس مُحدد لكن لا يوجد نقاط كافية → رجوع للكل
    if (want !== 'any' && getRandomDiamonds() < RANDOM_FILTER_COST) {
        want = 'any';
        setRandomWantUI('any');
        showRandomToast(currentLang() === 'ar' ? 'ليس لك عدد النقاط الكافي للاستمرار' : 'Not enough points to continue');
    }

    // لو الدولة محددة لكن لا يوجد اشتراك ولا نقاط 5 → رجوع للكل
    if (region !== 'all' && !hasRandomMonthly() && getRandomDiamonds() < RANDOM_COUNTRY_COST) {
        region = 'all';
        setRandomRegionValue('all');
        showRandomToast(currentLang() === 'ar' ? 'ليس لك عدد النقاط الكافي للاستمرار' : 'Not enough points to continue');
    }

    // حدث التفضيلات ثم ابدأ البحث (سيقوم الخصم إن لزم)
    randomWantSelection = want;
    startRandomSearchFromUI();
}

function getRandomDiamonds() {
    try {
        const n = parseInt(localStorage.getItem(RANDOM_DIAMOND_KEY) || '0', 10);
        return Number.isFinite(n) && n >= 0 ? n : 0;
    } catch {
        return 0;
    }
}

function setRandomDiamonds(n) {
    try {
        localStorage.setItem(RANDOM_DIAMOND_KEY, String(Math.max(0, n)));
    } catch {
        /* ignore */
    }
    const el = document.getElementById('randomDiamondCount');
    if (el) el.textContent = String(getRandomDiamonds());
    refreshRandomRegionSelectDisabledState();
}

function hasRandomMonthly() {
    try {
        const t = parseInt(localStorage.getItem(RANDOM_MONTHLY_UNTIL_KEY) || '0', 10);
        return Number.isFinite(t) && t > Date.now();
    } catch {
        return false;
    }
}

function flagUrlFromCC(alpha2, size = 40) {
    const u = String(alpha2 || '').toLowerCase();
    if (!/^[a-z]{2}$/.test(u)) return '';
    return `https://flagcdn.com/w${size}/${u}.png`;
}

function flagEmojiFromCC(alpha2) {
    const u = String(alpha2 || '').toUpperCase();
    if (!/^[A-Z]{2}$/.test(u)) return '🌐';
    const A = 0x1f1e6;
    return String.fromCodePoint(A + u.charCodeAt(0) - 65, A + u.charCodeAt(1) - 65);
}

function getAllRegionCodesForRandom() {
    try {
        if (typeof Intl !== 'undefined' && typeof Intl.supportedValuesOf === 'function') {
            const r = Intl.supportedValuesOf('region');
            return r.filter((c) => typeof c === 'string' && /^[A-Z]{2}$/.test(c));
        }
    } catch {
        /* ignore */
    }
    return RANDOM_REGION_CODES_FALLBACK.slice();
}

function refreshRandomRegionSelectDisabledState() {
    const sel = document.getElementById('randomRegionSelect');
    const menu = document.getElementById('randomRegionMenu');
    if (!sel || !menu) return;
    const canPickCountry = hasRandomMonthly() || getRandomDiamonds() >= RANDOM_COUNTRY_COST;
    menu.querySelectorAll('.random-region-picker__item').forEach((row) => {
        const isAll = row.getAttribute('data-code') === 'all';
        row.classList.toggle('is-disabled', !isAll && !canPickCountry);
        row.setAttribute('aria-disabled', (!isAll && !canPickCountry) ? 'true' : 'false');
    });
    if (!canPickCountry && sel.value !== 'all') sel.value = 'all';
    const selected = menu.querySelector(`.random-region-picker__item[data-code="${sel.value || 'all'}"]`);
    if (selected) selected.click();
}

function populateRandomRegionSelect(lang) {
    const sel = document.getElementById('randomRegionSelect');
    const menu = document.getElementById('randomRegionMenu');
    const btn = document.getElementById('randomRegionPickerBtn');
    const flag = document.getElementById('randomRegionFlag');
    const label = document.getElementById('randomRegionLabel');
    if (!sel || !menu || !btn || !flag || !label) return;
    const loc = lang || currentLang();
    const tBloc = translations[loc] || translations.en;
    const prev = (sel.value || 'all').toLowerCase();
    const locale = loc === 'ar' ? 'ar' : 'en';
    let dn;
    try {
        dn = new Intl.DisplayNames([locale], { type: 'region' });
    } catch {
        dn = null;
    }
    const codes = getAllRegionCodesForRandom().filter((code) => String(code).toUpperCase() !== 'EH');
    const items = codes.map((code) => {
        const up = String(code).toUpperCase();
        let name = up;
        try {
            if (dn) name = dn.of(up);
        } catch {
            /* keep */
        }
        if (up === 'PS') {
            name = loc === 'ar' ? 'فلسطين' : 'Palestine';
        }
        return { code: up.toLowerCase(), name };
    });
    const collator = new Intl.Collator(locale);
    items.sort((a, b) => collator.compare(a.name, b.name));
    menu.innerHTML = '';
    const allLabel = tBloc.randomRegAll || '🌐 All';
    const addMenuItem = (code, name) => {
        const row = document.createElement('button');
        row.type = 'button';
        row.className = 'random-region-picker__item';
        row.setAttribute('data-code', code);
        const img = document.createElement('img');
        img.className = 'random-region-picker__flag';
        img.loading = 'lazy';
        if (code === 'all') {
            img.src = '';
            img.alt = '';
            img.style.visibility = 'hidden';
        } else {
            img.src = flagUrlFromCC(code, 40);
            img.alt = '';
            img.referrerPolicy = 'no-referrer';
        }
        const txt = document.createElement('span');
        txt.textContent = name;
        row.appendChild(img);
        row.appendChild(txt);
        row.addEventListener('click', () => {
            if (row.classList.contains('is-disabled')) return;
            sel.value = code;
            menu.querySelectorAll('.random-region-picker__item').forEach((n) => n.classList.remove('is-selected'));
            row.classList.add('is-selected');
            label.textContent = name;
            if (code === 'all') {
                flag.src = '';
                flag.style.visibility = 'hidden';
            } else {
                flag.src = flagUrlFromCC(code, 40);
                flag.style.visibility = 'visible';
            }
            menu.classList.add('is-hidden');
            btn.setAttribute('aria-expanded', 'false');
        });
        menu.appendChild(row);
    };
    addMenuItem('all', allLabel);
    items.forEach((it) => {
        addMenuItem(it.code, it.name);
    });
    sel.value = prev;
    if (sel.value !== prev) sel.value = 'all';
    const selected = menu.querySelector(`.random-region-picker__item[data-code="${sel.value}"]`)
        || menu.querySelector('.random-region-picker__item[data-code="all"]');
    if (selected) selected.click();
    if (!randomRegionPickerBound) {
        btn.onclick = () => {
            menu.classList.toggle('is-hidden');
            btn.setAttribute('aria-expanded', menu.classList.contains('is-hidden') ? 'false' : 'true');
        };
        document.addEventListener('click', (ev) => {
            const picker = document.getElementById('randomRegionPicker');
            if (!picker || picker.contains(ev.target)) return;
            menu.classList.add('is-hidden');
            btn.setAttribute('aria-expanded', 'false');
        });
        randomRegionPickerBound = true;
    }
    refreshRandomRegionSelectDisabledState();
}

function syncRandomMatchPricesAndRegions() {
    document.querySelectorAll('#randomPriceFiltered, #randomPriceFiltered2').forEach((el) => {
        el.textContent = String(RANDOM_FILTER_COST);
    });
    populateRandomRegionSelect(currentLang());
}

function addRandomDiamonds(delta) {
    setRandomDiamonds(getRandomDiamonds() + delta);
}

function syncRandomFabVisibility() {
    const btn = document.getElementById('randomMatchTopBtn');
    if (!btn) return;
    const ci = document.getElementById('chatInterface');
    const app = document.getElementById('randomMatchApp');
    // chatInterface يبدأ مخفياً بـ .is-hidden دون style.display؛ المقارنة بـ style.display كانت تخفي الزر دائماً
    const inRoom = ci && window.getComputedStyle(ci).display !== 'none';
    const appOpen = app && window.getComputedStyle(app).display !== 'none';
    btn.classList.toggle('is-hidden', inRoom || appOpen);
}

function showRandomSubView(which) {
    const lobby = document.getElementById('randomLobbyView');
    const search = document.getElementById('randomSearchView');
    const chat = document.getElementById('randomChatView');
    if (lobby) lobby.classList.toggle('is-hidden', which !== 'lobby');
    if (search) search.classList.toggle('is-hidden', which !== 'search');
    if (chat) chat.classList.toggle('is-hidden', which !== 'chat');
}

function openRandomMatchApp() {
    if (isGuestUser()) {
        alert(currentLang() === 'ar'
            ? 'يجب إنشاء حساب/تسجيل الدخول لاستخدام الدردشة العشوائية.'
            : 'You must create an account / login to use random chat.');
        return;
    }
    const app = document.getElementById('randomMatchApp');
    if (!app) return;
    app.classList.remove('is-hidden');
    app.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
    setRandomDiamonds(getRandomDiamonds());
    syncRandomMatchPricesAndRegions();
    showRandomSubView('lobby');
    randomWantSelection = 'any';
    randomChatMode = 'text';
    document.querySelectorAll('.random-gender-card').forEach((c) => {
        c.classList.toggle('random-gender-card--active', c.getAttribute('data-want') === 'any');
    });
    document.getElementById('randomModeText')?.classList.add('random-mode-toggle__btn--active');
    document.getElementById('randomModeVoice')?.classList.remove('random-mode-toggle__btn--active');
    syncRandomFabVisibility();
    updateI18nPlaceholders(currentLang());
}

function closeRandomMatchApp() {
    const app = document.getElementById('randomMatchApp');
    if (!app) return;
    if (randomLastPaidForFilter) {
        addRandomDiamonds(RANDOM_FILTER_COST);
        randomLastPaidForFilter = false;
    }
    if (randomLastPaidForCountry) {
        addRandomDiamonds(RANDOM_COUNTRY_COST);
        randomLastPaidForCountry = false;
    }
    if (socket) {
        socket.emit('randomCancelSearch');
        socket.emit('randomSkip');
    }
    app.classList.add('is-hidden');
    app.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
    const area = document.getElementById('randomChatMessages');
    if (area) area.innerHTML = '';
    syncRandomFabVisibility();
}

function appendRandomChatLine(text, time, isMine) {
    const area = document.getElementById('randomChatMessages');
    if (!area) return;
    const row = document.createElement('div');
    row.className = 'random-msg-row ' + (isMine ? 'random-msg-row--mine' : 'random-msg-row--peer');
    const bubble = document.createElement('div');
    bubble.className = 'random-msg-bubble';
    const t = document.createElement('p');
    t.className = 'random-msg-text';
    t.textContent = sanitizeInput(text);
    const tm = document.createElement('span');
    tm.className = 'random-msg-meta';
    tm.textContent = time || '';
    bubble.appendChild(t);
    bubble.appendChild(tm);
    row.appendChild(bubble);
    area.appendChild(row);
    area.scrollTop = area.scrollHeight;
}

function startRandomSearchFromUI() {
    if (!socket) {
        alert(tKey('randomNeedNick'));
        return;
    }
    if (isGuestUser()) {
        alert(currentLang() === 'ar'
            ? 'يجب إنشاء حساب/تسجيل الدخول لاستخدام الدردشة العشوائية.'
            : 'You must create an account / login to use random chat.');
        return;
    }
    const nick = getSecureItem('nickname') || '';
    if (!nick || nick === 'Guest') {
        alert(tKey('randomNeedNick'));
        return;
    }
    const want = randomWantSelection === 'male' || randomWantSelection === 'female' ? randomWantSelection : 'any';
    const region = (document.getElementById('randomRegionSelect')?.value || 'all').toLowerCase();
    const costGender = want !== 'any' ? RANDOM_FILTER_COST : 0;
    const costCountry = region !== 'all' && !hasRandomMonthly() ? RANDOM_COUNTRY_COST : 0;
    const totalCost = costGender + costCountry;
    if (getRandomDiamonds() < totalCost) {
        const lines = [tKey('randomLowPoints')];
        if (costGender > 0) lines.push(tKey('randomLowGender'));
        if (costCountry > 0) lines.push(tKey('randomLowCountry'));
        alert(lines.filter(Boolean).join('\n'));
        return;
    }
    randomLastPaidForFilter = costGender > 0;
    randomLastPaidForCountry = costCountry > 0;
    if (totalCost > 0) setRandomDiamonds(getRandomDiamonds() - totalCost);
    randomLastSearchPrefs = { want, region, mode: randomChatMode };
    const gender = getSecureItem('gender') || 'male';
    showRandomSubView('search');
    socket.emit('randomJoinSearch', {
        username: nick,
        gender,
        want,
        region,
        mode: randomChatMode
    });
}

function wireRandomMatchUI() {
    document.getElementById('randomMatchTopBtn')?.addEventListener('click', () => openRandomMatchApp());
    document.getElementById('randomMatchBackdrop')?.addEventListener('click', () => closeRandomMatchApp());
    document.getElementById('randomCloseLobbyBtn')?.addEventListener('click', () => closeRandomMatchApp());

    document.getElementById('randomEarnPointsBtn')?.addEventListener('click', () => {
        openModal(document.getElementById('randomPointsModal'));
    });
    document.getElementById('randomPointsModalClose')?.addEventListener('click', () => {
        closeModalEl(document.getElementById('randomPointsModal'));
    });

    document.getElementById('randomOptMonthly')?.addEventListener('click', () => {
        try {
            localStorage.setItem(RANDOM_MONTHLY_UNTIL_KEY, String(Date.now() + 30 * 86400000));
        } catch {
            /* ignore */
        }
        closeModalEl(document.getElementById('randomPointsModal'));
        alert(tKey('randomMonthlyActivated'));
        refreshRandomRegionSelectDisabledState();
    });
    document.getElementById('randomOptBuy')?.addEventListener('click', () => alert(tKey('randomSoon')));
    document.getElementById('randomOptFreeAd')?.addEventListener('click', () => {
        closeModalEl(document.getElementById('randomPointsModal'));
        const adm = document.getElementById('randomAdModal');
        const bar = document.getElementById('randomAdProgressBar');
        const btn = document.getElementById('randomAdCloseBtn');
        if (!adm || !bar || !btn) return;
        if (randomAdProgressTimer) {
            clearInterval(randomAdProgressTimer);
            randomAdProgressTimer = null;
        }
        openModal(adm);
        btn.disabled = true;
        bar.style.width = '0%';
        const waitEl = document.getElementById('t-randomAdWait');
        if (waitEl) waitEl.textContent = tKey('randomAdWait');
        const t0 = Date.now();
        randomAdProgressTimer = setInterval(() => {
            const p = Math.min(100, ((Date.now() - t0) / 4500) * 100);
            bar.style.width = `${p}%`;
            if (p >= 100) {
                clearInterval(randomAdProgressTimer);
                randomAdProgressTimer = null;
                addRandomDiamonds(RANDOM_AD_REWARD);
                btn.disabled = false;
                if (waitEl) waitEl.textContent = tKey('randomAdDone');
            }
        }, 80);
    });
    document.getElementById('randomAdCloseBtn')?.addEventListener('click', () => {
        const btn = document.getElementById('randomAdCloseBtn');
        if (btn?.disabled) return;
        if (randomAdProgressTimer) {
            clearInterval(randomAdProgressTimer);
            randomAdProgressTimer = null;
        }
        closeModalEl(document.getElementById('randomAdModal'));
    });

    document.getElementById('randomModeText')?.addEventListener('click', () => {
        randomChatMode = 'text';
        document.getElementById('randomModeText')?.classList.add('random-mode-toggle__btn--active');
        document.getElementById('randomModeVoice')?.classList.remove('random-mode-toggle__btn--active');
    });
    document.getElementById('randomModeVoice')?.addEventListener('click', () => {
        alert(tKey('randomVoiceSoon'));
    });

    ['randomPickMale', 'randomPickFemale', 'randomPickAll'].forEach((id) => {
        document.getElementById(id)?.addEventListener('click', (ev) => {
            const btn = ev.currentTarget;
            const want = btn.getAttribute('data-want') || 'any';
            randomWantSelection = want;
            document.querySelectorAll('.random-gender-card').forEach((c) => {
                c.classList.toggle('random-gender-card--active', c.getAttribute('data-want') === want);
            });
        });
    });

    document.getElementById('randomStartBtn')?.addEventListener('click', () => startRandomSearchFromUI());
    document.getElementById('randomCancelSearchBtn')?.addEventListener('click', () => {
        if (randomLastPaidForFilter) {
            addRandomDiamonds(RANDOM_FILTER_COST);
            randomLastPaidForFilter = false;
        }
        if (randomLastPaidForCountry) {
            addRandomDiamonds(RANDOM_COUNTRY_COST);
            randomLastPaidForCountry = false;
        }
        socket?.emit('randomCancelSearch');
        showRandomSubView('lobby');
    });

    const skipHandler = () => {
        randomLastPaidForFilter = false;
        randomLastPaidForCountry = false;
        randomBackToLobbyWanted = false;
        randomAutoRestartWanted = true;
        socket?.emit('randomSkip');
        showRandomSubView('lobby');
        const area = document.getElementById('randomChatMessages');
        if (area) area.innerHTML = '';
        const title = document.getElementById('randomPartnerTitle');
        if (title) title.textContent = '…';
    };
    document.getElementById('randomSkipBtn')?.addEventListener('click', skipHandler);
    // زر الرجوع: يرجع للّوبي (اختيار الدولة/الجنس) بدون إعادة بحث تلقائي
    document.getElementById('randomChatBackBtn')?.addEventListener('click', () => {
        randomLastPaidForFilter = false;
        randomLastPaidForCountry = false;
        randomAutoRestartWanted = false;
        randomBackToLobbyWanted = true;
        socket?.emit('randomSkip'); // إنهاء الجلسة الحالية، ثم نعود للّوبي فقط
        showRandomSubView('lobby');
        const area = document.getElementById('randomChatMessages');
        if (area) area.innerHTML = '';
        const title = document.getElementById('randomPartnerTitle');
        if (title) title.textContent = '…';
    });

    document.getElementById('randomChatSendBtn')?.addEventListener('click', () => {
        const inp = document.getElementById('randomChatInput');
        const v = (inp?.value || '').trim();
        if (!v || !socket) return;
        socket.emit('randomChatMessage', { text: v });
        appendRandomChatLine(v, new Date().toLocaleTimeString(), true);
        if (inp) inp.value = '';
    });
    document.getElementById('randomChatInput')?.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter' || e.shiftKey) return;
        e.preventDefault();
        document.getElementById('randomChatSendBtn')?.click();
    });
}

const AVATAR_STORAGE_KEY = 'userAvatar';
const COVER_STORAGE_KEY = 'userCoverPhoto';

function rememberPeerFromListUser(user) {
    if (!user || !user.username) return;
    const key = String(user.username).toLowerCase();
    const cur = peerProfileCache.get(key) || {};
    peerProfileCache.set(key, {
        avatar: 'avatar' in user ? user.avatar : cur.avatar,
        coverPhoto: 'coverPhoto' in user ? user.coverPhoto : cur.coverPhoto
    });
}

function getPeerProfile(username) {
    if (!username) return {};
    return peerProfileCache.get(String(username).toLowerCase()) || {};
}

function updatePrivateChatHeader(peer) {
    const meta = getPeerProfile(peer);
    const coverImg = document.getElementById('privatePeerCoverImg');
    const coverFb = document.getElementById('privatePeerCoverFallback');
    const badge = document.getElementById('privatePeerAvatarBadge');
    const badgeImg = document.getElementById('privatePeerBadgeAvatar');
    const badgeLetter = document.getElementById('privatePeerBadgeLetter');
    const safe = sanitizeInput(peer);
    if (coverImg && coverFb) {
        coverFb.style.setProperty('--av-hue', String(avatarHueFromString(peer)));
        if (meta.coverPhoto) {
            coverImg.src = meta.coverPhoto;
            coverImg.classList.remove('is-hidden');
            coverFb.classList.add('is-hidden');
        } else {
            coverImg.removeAttribute('src');
            coverImg.classList.add('is-hidden');
            coverFb.classList.remove('is-hidden');
        }
    }
    if (badge && badgeImg && badgeLetter) {
        badge.style.setProperty('--av-hue', String(avatarHueFromString(peer)));
        if (meta.avatar) {
            badgeImg.src = meta.avatar;
            badgeImg.classList.remove('is-hidden');
            badge.classList.add('pm-peer-badge--has-photo');
        } else {
            badgeImg.removeAttribute('src');
            badgeImg.classList.add('is-hidden');
            badge.classList.remove('pm-peer-badge--has-photo');
            const ch = safe.charAt(0);
            badgeLetter.textContent = ch ? ch.toUpperCase() : '…';
        }
    }
}

function openMediaLightbox(src) {
    if (!src) return;
    const box = document.getElementById('mediaLightbox');
    const img = document.getElementById('mediaLightboxImg');
    if (!box || !img) return;
    img.src = src;
    box.classList.remove('is-hidden');
    document.body.style.overflow = 'hidden';
}

function closeMediaLightbox() {
    const box = document.getElementById('mediaLightbox');
    const img = document.getElementById('mediaLightboxImg');
    if (box) box.classList.add('is-hidden');
    if (img) img.removeAttribute('src');
    document.body.style.overflow = '';
}

function bindChatMediaOpen(img) {
    if (!img || img.dataset.mediaLightboxBound === '1') return;
    img.dataset.mediaLightboxBound = '1';
    img.classList.add('chat-media-thumb');
    img.addEventListener('click', () => openMediaLightbox(img.src));
    img.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            openMediaLightbox(img.src);
        }
    });
    img.tabIndex = 0;
    img.setAttribute('role', 'button');
}

function getAvatarUrl() {
    try {
        return localStorage.getItem(AVATAR_STORAGE_KEY) || '';
    } catch {
        return '';
    }
}

function setAvatarUrl(dataUrl) {
    try {
        if (dataUrl) localStorage.setItem(AVATAR_STORAGE_KEY, dataUrl);
        else localStorage.removeItem(AVATAR_STORAGE_KEY);
    } catch (e) {
        /* ignore quota */
    }
}

function getCoverUrl() {
    try {
        return localStorage.getItem(COVER_STORAGE_KEY) || '';
    } catch {
        return '';
    }
}

function setCoverUrl(dataUrl) {
    try {
        if (dataUrl) localStorage.setItem(COVER_STORAGE_KEY, dataUrl);
        else localStorage.removeItem(COVER_STORAGE_KEY);
    } catch (e) {
        /* ignore quota */
    }
}

function emitProfileMediaToRoom() {
    if (!socket || !currentRoom) return;
    socket.emit('updateProfileMedia', {
        avatar: getAvatarUrl() || null,
        coverPhoto: getCoverUrl() || null
    });
}

async function handleAvatarFile(event) {
    const file = event.target.files[0];
    if (!file) return;
    if (!isValidImage(file)) {
        alert(currentLang() === 'ar' ? 'صيغة الصورة غير مدعومة' : 'Unsupported image format');
        event.target.value = '';
        return;
    }
    if (file.size > 1024 * 1024) {
        alert(currentLang() === 'ar' ? 'الصورة كبيرة جداً (الحد 1 ميجابايت)' : 'Image too large (max 1 MB)');
        event.target.value = '';
        return;
    }
    try {
        const dataUrl = await compressImageFileToDataUrl(file, { maxDim: 400, maxBytes: 950 * 1024 });
        setAvatarUrl(dataUrl);
        refreshAvatarUI();
        emitProfileMediaToRoom();
    } catch {
        alert(currentLang() === 'ar' ? 'تعذّر معالجة الصورة' : 'Could not process image');
    }
    event.target.value = '';
}

function handleCoverFile(event) {
    const file = event.target.files[0];
    if (!file) return;
    if (!isValidImage(file) || !/^image\/(jpeg|png|webp)$/i.test(file.type)) {
        alert(currentLang() === 'ar' ? 'الغلاف: JPG أو PNG أو WebP فقط' : 'Cover: JPG, PNG or WebP only');
        event.target.value = '';
        return;
    }
    if (file.size > 1.25 * 1024 * 1024) {
        alert(currentLang() === 'ar' ? 'صورة الغلاف كبيرة جداً (الحد ~1.2 ميجابايت)' : 'Cover image too large (max ~1.2 MB)');
        event.target.value = '';
        return;
    }
    const reader = new FileReader();
    reader.onload = () => {
        setCoverUrl(reader.result);
        refreshCoverUI();
        emitProfileMediaToRoom();
    };
    reader.readAsDataURL(file);
    event.target.value = '';
}

function refreshCoverUI() {
    const url = getCoverUrl();
    const prev = document.getElementById('coverPreview');
    const ph = document.getElementById('coverPlaceholder');
    if (prev && ph) {
        if (url) {
            prev.src = url;
            prev.classList.remove('is-hidden');
            ph.style.display = 'none';
        } else {
            prev.removeAttribute('src');
            prev.classList.add('is-hidden');
            ph.style.display = 'block';
        }
    }
}

function refreshAvatarUI() {
    const url = getAvatarUrl();
    const prev = document.getElementById('avatarPreview');
    const ph = document.getElementById('avatarPlaceholder');
    const mini = document.getElementById('userAvatarMini');
    const miniPh = document.getElementById('userAvatarMiniPh');
    if (prev && ph) {
        if (url) {
            prev.src = url;
            prev.classList.add('visible');
            ph.style.display = 'none';
        } else {
            prev.removeAttribute('src');
            prev.classList.remove('visible');
            ph.style.display = 'block';
        }
    }
    if (mini && miniPh) {
        if (url) {
            mini.src = url;
            mini.style.display = 'block';
            miniPh.style.display = 'none';
        } else {
            mini.removeAttribute('src');
            mini.style.display = 'none';
            miniPh.style.display = 'block';
        }
    }
}

function fillSelectOptions(selectId, lang, rows) {
    const sel = document.getElementById(selectId);
    if (!sel) return;
    const cur = sel.value;
    sel.innerHTML = '';
    rows.forEach(([value, enLabel, arLabel]) => {
        const opt = document.createElement('option');
        opt.value = value;
        opt.textContent = lang === 'ar' ? arLabel : enLabel;
        sel.appendChild(opt);
    });
    if ([...sel.options].some((o) => o.value === cur)) sel.value = cur;
}

/** ذكر أزرق ♀ / أنثى وردي — على قوائم الجنس في الملف الشخصي والتسجيل */
function syncGenderSelectStyle() {
    ['userGender', 'regGenderInput'].forEach((id) => {
        const el = document.getElementById(id);
        if (!el) return;
        el.classList.remove('gender-select--male', 'gender-select--female', 'gender-select--other');
        const v = el.value || 'male';
        if (v === 'female') el.classList.add('gender-select--female');
        else if (v === 'other') el.classList.add('gender-select--other');
        else el.classList.add('gender-select--male');
    });
}

function updateProfileI18n(lang) {
    const t = translations[lang];
    if (!t) return;

    fillSelectOptions('userGender', lang, [
        ['male', translations.en.optMale, translations.ar.optMale],
        ['female', translations.en.optFemale, translations.ar.optFemale],
        ['other', translations.en.optOther, translations.ar.optOther]
    ]);
    fillSelectOptions('userRelationship', lang, [
        ['', translations.en.relNotSpecified, translations.ar.relNotSpecified],
        ['single', translations.en.relSingle, translations.ar.relSingle],
        ['married', translations.en.relMarried, translations.ar.relMarried],
        ['in_relationship', translations.en.relInRelationship, translations.ar.relInRelationship],
        ['complicated', translations.en.relComplicated, translations.ar.relComplicated]
    ]);
    fillSelectOptions('userChatLang', lang, [
        ['en', translations.en.langEn, translations.ar.langEn],
        ['ar', translations.en.langAr, translations.ar.langAr]
    ]);
    fillSelectOptions('privacyImages', lang, [
        ['everyone', translations.en.privacyEveryone, translations.ar.privacyEveryone],
        ['friends', translations.en.privacyFriends, translations.ar.privacyFriends],
        ['nobody', translations.en.privacyNobody, translations.ar.privacyNobody]
    ]);
    fillSelectOptions('privacyPrivateChat', lang, [
        ['on', translations.en.privateChatOn, translations.ar.privateChatOn],
        ['off', translations.en.privateChatOff, translations.ar.privateChatOff]
    ]);
    fillSelectOptions('privacyOnlineStatus', lang, [
        ['on', translations.en.onlineShow, translations.ar.onlineShow],
        ['off', translations.en.onlineHide, translations.ar.onlineHide]
    ]);
    fillSelectOptions('notifSounds', lang, [
        ['all', translations.en.notifAllSounds, translations.ar.notifAllSounds],
        ['mentions', translations.en.notifMentions, translations.ar.notifMentions],
        ['none', translations.en.notifMute, translations.ar.notifMute]
    ]);
    fillSelectOptions('notifJoinLeave', lang, [
        ['on', translations.en.notifJoinShow, translations.ar.notifJoinShow],
        ['off', translations.en.notifJoinHide, translations.ar.notifJoinHide]
    ]);
    fillSelectOptions('notifTheme', lang, [
        ['dark', translations.en.themeDark, translations.ar.themeDark],
        ['light', translations.en.themeLight, translations.ar.themeLight],
        ['glass', translations.en.themeGlass, translations.ar.themeGlass]
    ]);

    const phUser = document.getElementById('userDisplayName');
    if (phUser) phUser.placeholder = t.phUsername;
    const phAge = document.getElementById('userAge');
    if (phAge) phAge.placeholder = t.phAge;
    const phBio = document.getElementById('userBio');
    if (phBio) phBio.placeholder = t.phBio;
    const phEm = document.getElementById('userEmail');
    if (phEm) phEm.placeholder = t.phEmail;
    const phPw = document.getElementById('userPassword');
    if (phPw) phPw.placeholder = t.phPassword;
    syncGenderSelectStyle();
}

function updateI18nPlaceholders(lang) {
    const t = translations[lang];
    if (!t) return;
    document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
        const key = el.getAttribute('data-i18n-placeholder');
        if (key && t[key]) el.placeholder = t[key];
    });
}

function updateRoomOnlineLabels(lang) {
    const t = translations[lang];
    if (!t || !t.onlineLabel) return;
    document.querySelectorAll('.room-online-label').forEach((el) => {
        el.textContent = t.onlineLabel;
    });
}

function currentLang() {
    return getSecureItem('lang') || 'en';
}

function tKey(key) {
    const lang = currentLang();
    return (translations[lang] && translations[lang][key]) || (translations.en[key] || '');
}

function messageForOauthErr(code) {
    const k = `oauthErr_${String(code || '').replace(/[^a-z0-9_]/gi, '_')}`;
    const msg = tKey(k);
    if (msg) return msg;
    return currentLang() === 'ar'
        ? 'تعذّر إكمال تسجيل الدخول بجوجل.'
        : 'Could not complete Google sign-in.';
}

/** بعد OAuth (كوكي فقط) أو فتح تبويب جديد — املأ authType/nickname من الجلسة */
async function syncMemberSessionFromCookie() {
    if (getSecureItem('authType') === 'member') return;
    try {
        const r = await secureFetch('/api/auth/verify');
        if (!r.ok) return;
        const data = await r.json().catch(() => ({}));
        if (data.valid && data.username) {
            setSecureItem('authType', 'member');
            setSecureItem('nickname', data.username);
        }
    } catch {
        /* ignore */
    }
}

function updateTexts(lang) {
    const t = translations[lang];
    if (!t) return;

    document.querySelectorAll('[id^="t-"]').forEach((el) => {
        const key = el.id.replace('t-', '');
        if (t[key]) el.innerText = t[key];
    });

    const welcomeEl = document.getElementById('t-welcome');
    if (welcomeEl) {
        const nick = getSecureItem('nickname') || 'Guest';
        welcomeEl.innerHTML = t.welcome + `<span id="displayNick" class="highlight-name">${sanitizeInput(nick)}</span>!`;
    }
    document.body.classList.toggle('ar', lang === 'ar');
    document.documentElement.lang = lang === 'ar' ? 'ar' : 'en';
    populateCountrySelect(lang);
    updateProfileI18n(lang);
    updateI18nPlaceholders(lang);
    updateRoomOnlineLabels(lang);
    refreshAvatarUI();
    refreshCoverUI();
    renderNotifications();
    const mUser = document.getElementById('memberUsernameInput');
    if (mUser) mUser.placeholder = t.memberUsernamePh || 'Username';
    const mPass = document.getElementById('memberPasswordInput');
    if (mPass) mPass.placeholder = t.memberPasswordPh || 'Password';
    const mBtn = document.getElementById('confirmMemberLogin');
    if (mBtn) mBtn.textContent = t.memberLoginBtn || 'Login';
    const reportReasonSel = document.getElementById('reportReasonSelect');
    if (reportReasonSel) {
        const options = [
            { value: 'harassment', label: t.reasonHarassment || 'Harassment' },
            { value: 'abusive_language', label: t.reasonAbusiveLanguage || 'Abusive language' },
            { value: 'explicit_image', label: t.reasonExplicitImage || 'Explicit image' },
            { value: 'spam', label: t.reasonSpam || 'Spam / annoyance' },
            { value: 'other', label: t.reasonOther || 'Other' }
        ];
        const current = reportReasonSel.value || 'harassment';
        reportReasonSel.innerHTML = '';
        options.forEach((row) => {
            const opt = document.createElement('option');
            opt.value = row.value;
            opt.textContent = row.label;
            reportReasonSel.appendChild(opt);
        });
        reportReasonSel.value = current;
    }
    const reportDetailsInput = document.getElementById('reportDetailsInput');
    if (reportDetailsInput) reportDetailsInput.placeholder = t.reportDetails || 'Additional details (optional)';
    syncRandomFabVisibility();
    setRandomDiamonds(getRandomDiamonds());
    populateRandomRegionSelect(lang);
    const rtb = document.getElementById('randomMatchTopBtn');
    if (rtb && t.randomTopTooltip) {
        rtb.setAttribute('title', t.randomTopTooltip);
        rtb.setAttribute('aria-label', t.randomTopTooltip);
    }
}

function addNotification(text) {
    notifications.unshift({
        text: sanitizeInput(text),
        time: getCurrentTime(),
        read: false
    });
    updateNotificationBadge();
    renderNotifications();
}

function updateNotificationBadge() {
    const badge = document.querySelector('#notificationsBtn .badge');
    if (!badge) return;
    const unread = notifications.filter((n) => !n.read).length;
    badge.textContent = unread > 0 ? String(unread) : '';
    badge.style.display = unread > 0 ? 'inline-block' : 'none';
}

function renderNotifications() {
    const list = document.getElementById('notificationsList');
    const empty = document.getElementById('t-notificationsEmpty');
    if (!list) return;
    list.innerHTML = '';
    if (!notifications.length) {
        if (empty) empty.style.display = 'block';
        return;
    }
    if (empty) empty.style.display = 'none';
    notifications.forEach((n) => {
        const row = document.createElement('div');
        row.className = 'inbox-row notif-popover-row';
        row.innerHTML = `<div class="inbox-row-main"><div class="notif-popover-text">${sanitizeInput(n.text)}</div><div class="inbox-preview">${n.time}</div></div>${n.read ? '' : '<span class="unread-dot"></span>'}`;
        list.appendChild(row);
    });
}

function isNotificationsPopoverOpen() {
    const pop = document.getElementById('notificationsPopover');
    return !!(pop && !pop.classList.contains('is-hidden'));
}

function openNotificationsPopover() {
    closeMessagesPopover();
    const pop = document.getElementById('notificationsPopover');
    const btn = document.getElementById('notificationsBtn');
    if (!pop) return;
    notifications.forEach((n) => {
        n.read = true;
    });
    updateNotificationBadge();
    renderNotifications();
    pop.classList.remove('is-hidden');
    btn?.setAttribute('aria-expanded', 'true');
}

function closeNotificationsPopover() {
    const pop = document.getElementById('notificationsPopover');
    const btn = document.getElementById('notificationsBtn');
    if (pop) pop.classList.add('is-hidden');
    btn?.setAttribute('aria-expanded', 'false');
}

function toggleNotificationsPopover(ev) {
    if (ev) ev.stopPropagation();
    if (isNotificationsPopoverOpen()) closeNotificationsPopover();
    else openNotificationsPopover();
}

function openNotificationsModal() {
    openNotificationsPopover();
}

function closeNotificationsModal() {
    closeNotificationsPopover();
}

function closeUserContextMenu() {
    const menu = document.getElementById('userContextMenu');
    if (menu) menu.style.display = 'none';
    contextTargetUser = '';
}

function openUserContextMenu(evt, username) {
    const menu = document.getElementById('userContextMenu');
    if (!menu) return;
    contextTargetUser = username;
    menu.style.display = 'block';
    const gap = 8;
    const rect = menu.getBoundingClientRect();
    let x = evt.clientX + gap;
    let y = evt.clientY - 8;
    if (x + rect.width > window.innerWidth - 8) x = window.innerWidth - rect.width - 8;
    if (y + rect.height > window.innerHeight - 8) y = window.innerHeight - rect.height - 8;
    if (y < 8) y = 8;
    menu.style.left = `${x}px`;
    menu.style.top = `${y}px`;
}

function getBlockedUsers() {
    try {
        const raw = localStorage.getItem('blockedUsers') || '[]';
        const arr = JSON.parse(raw);
        if (!Array.isArray(arr)) return [];
        return arr.map((v) => String(v || '').trim().toLowerCase()).filter(Boolean);
    } catch {
        return [];
    }
}

function setBlockedUsers(rows) {
    localStorage.setItem('blockedUsers', JSON.stringify(Array.from(new Set(rows))));
}

function isBlockedUser(username) {
    const key = String(username || '').trim().toLowerCase();
    if (!key) return false;
    return getBlockedUsers().includes(key);
}

function blockUserLocal(username) {
    const key = String(username || '').trim().toLowerCase();
    if (!key) return;
    const blocked = getBlockedUsers();
    if (!blocked.includes(key)) blocked.push(key);
    setBlockedUsers(blocked);
}

function showReportToast(msg) {
    const toast = document.getElementById('reportToast');
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.remove('is-hidden');
    requestAnimationFrame(() => toast.classList.add('is-show'));
    setTimeout(() => {
        toast.classList.remove('is-show');
        setTimeout(() => toast.classList.add('is-hidden'), 250);
    }, 2200);
}

function saveReportLocal(payload) {
    try {
        const raw = localStorage.getItem('moderationReports') || '[]';
        const rows = JSON.parse(raw);
        const list = Array.isArray(rows) ? rows : [];
        list.unshift(payload);
        localStorage.setItem('moderationReports', JSON.stringify(list.slice(0, 500)));
    } catch {
        /* ignore storage issues */
    }
}

function openReportModal(username) {
    moderationTargetUser = String(username || '').trim();
    const modal = document.getElementById('reportModal');
    const label = document.getElementById('reportTargetLabel');
    if (label) label.textContent = `${tKey('reportAgainst')} ${sanitizeInput(moderationTargetUser)}`;
    const details = document.getElementById('reportDetailsInput');
    if (details) details.value = '';
    const reason = document.getElementById('reportReasonSelect');
    if (reason) reason.value = 'harassment';
    openModal(modal);
}

function openBlockConfirmModal(username) {
    moderationTargetUser = String(username || '').trim();
    const modal = document.getElementById('blockConfirmModal');
    const label = document.getElementById('blockTargetLabel');
    if (label) label.textContent = `${tKey('targetUser')}: ${sanitizeInput(moderationTargetUser)}`;
    openModal(modal);
}

function populateCountrySelect(lang) {
    const sel = document.getElementById('userCountry');
    if (!sel || typeof Intl === 'undefined' || !Intl.DisplayNames) return;
    const locale = lang === 'ar' ? 'ar' : 'en';
    const dn = new Intl.DisplayNames([locale], { type: 'region' });
    const codes = getAllRegionCodesForRandom().filter((c) => String(c).toUpperCase() !== 'EH');
    const current = sel.value;
    sel.innerHTML = `<option value="">${lang === 'ar' ? 'اختر الدولة' : 'Select Country'}</option>`;
    const items = codes.map((code) => {
        const up = String(code).toUpperCase();
        let name = up;
        try {
            name = dn.of(up);
        } catch {
            /* keep fallback */
        }
        if (up === 'PS') name = lang === 'ar' ? 'فلسطين' : 'Palestine';
        return { code: up, name, flag: flagEmojiFromCC(up) };
    });
    const collator = new Intl.Collator(locale);
    items.sort((a, b) => collator.compare(a.name, b.name));
    items.forEach((it) => {
        const opt = document.createElement('option');
        opt.value = it.code;
        opt.textContent = `${it.flag} ${it.name}`;
        sel.appendChild(opt);
    });
    if (current) sel.value = current;
}

function initRoomCards() {
    document.querySelectorAll('.room-card').forEach((card) => {
        const fg = card.querySelector('.flag-bg');
        if (!fg) return;
        const roomName = String(card.getAttribute('data-room') || '').toLowerCase();
        if (card.getAttribute('data-room-kind') === 'girls') {
            fg.innerHTML = '';
            fg.classList.remove('flag-composite');
            fg.classList.add('flag-bg--girls-art');
            return;
        }
        if (roomName === 'islamiyat') {
            fg.innerHTML = '';
            fg.classList.remove('flag-composite', 'flag-bubbles');
            fg.classList.add('flag-bg--islamiyat');
            const img = document.createElement('img');
            img.src = '/images/islamiyat-room-icon.png';
            img.alt = 'Islamiyat room icon';
            img.loading = 'lazy';
            img.className = 'islamiyat-room-icon';
            fg.appendChild(img);
            return;
        }
        const region = card.getAttribute('data-region');
        if (region && REGION_FLAGS[region]) {
            fg.innerHTML = '';
            fg.classList.remove('flag-composite');
            fg.classList.add('flag-bubbles');
            REGION_FLAGS[region].forEach((c) => {
                const img = document.createElement('img');
                img.src = `${FLAG_CDN}/${c}.png`;
                img.alt = '';
                img.loading = 'lazy';
                img.referrerPolicy = 'no-referrer';
                img.className = 'flag-bubble';
                fg.appendChild(img);
            });
            return;
        }
        const code = card.getAttribute('data-code');
        if (code) {
            fg.innerHTML = '';
            fg.classList.remove('flag-composite');
            const img = document.createElement('img');
            img.src = `${FLAG_CDN}/${code}.png`;
            img.alt = '';
            img.loading = 'lazy';
            img.referrerPolicy = 'no-referrer';
            fg.appendChild(img);
        }
    });
}

function syncEmojiPickerTheme() {
    /* لوحة الإيموجي تتبع `body.rooms-page.light` في style.css */
}

function toggleTheme() {
    const isLight = document.body.classList.toggle('light');
    setSecureItem('theme', isLight ? 'light' : 'dark');
    const themeBtn = document.getElementById('themeToggle');
    if (themeBtn) themeBtn.innerText = isLight ? '☀️' : '🌙';
    syncEmojiPickerTheme();
}

function openProfileModal() {
    const modal = document.getElementById('profileModal');
    if (modal) {
        updateProfileI18n(currentLang());
        loadProfileForm();
        refreshAvatarUI();
        refreshCoverUI();
        openModal(modal);
    }
}

function loadProfileForm() {
    const nick = getSecureItem('nickname');
    const el = document.getElementById('userDisplayName');
    if (el && nick) el.value = nick;
    const g = getSecureItem('gender');
    if (g && document.getElementById('userGender')) document.getElementById('userGender').value = g;
    const age = getSecureItem('age');
    if (age && document.getElementById('userAge')) document.getElementById('userAge').value = age;
    const c = getSecureItem('countryCode');
    if (c && document.getElementById('userCountry')) document.getElementById('userCountry').value = c;
    const rel = getSecureItem('relationship');
    if (rel && document.getElementById('userRelationship')) document.getElementById('userRelationship').value = rel;
    const bio = getSecureItem('bio');
    if (bio && document.getElementById('userBio')) document.getElementById('userBio').value = bio;
    const pi = getSecureItem('privacyImages');
    if (pi && document.getElementById('privacyImages')) document.getElementById('privacyImages').value = pi;
    const pp = getSecureItem('privacyPrivateChat');
    if (pp && document.getElementById('privacyPrivateChat')) document.getElementById('privacyPrivateChat').value = pp;
    const po = getSecureItem('privacyOnlineStatus');
    if (po && document.getElementById('privacyOnlineStatus')) document.getElementById('privacyOnlineStatus').value = po;
    const langPref = getSecureItem('lang') || 'en';
    const ucl = document.getElementById('userChatLang');
    if (ucl) ucl.value = langPref;
    const em = getSecureItem('userEmail');
    if (em && document.getElementById('userEmail')) document.getElementById('userEmail').value = em;
    const tz = getSecureItem('userTimezone');
    if (tz && document.getElementById('userTimezone')) document.getElementById('userTimezone').value = tz;
    const ns = getSecureItem('notifSounds');
    if (ns && document.getElementById('notifSounds')) document.getElementById('notifSounds').value = ns;
    const nj = getSecureItem('notifJoinLeave');
    if (nj && document.getElementById('notifJoinLeave')) document.getElementById('notifJoinLeave').value = nj;
    const nt = getSecureItem('notifTheme');
    if (nt && document.getElementById('notifTheme')) document.getElementById('notifTheme').value = nt;
    syncGenderSelectStyle();
}

function closeProfileModal() {
    const modal = document.getElementById('profileModal');
    closeModalEl(modal);
}

function isMessagesPopoverOpen() {
    const pop = document.getElementById('messagesPopover');
    return !!(pop && !pop.classList.contains('is-hidden'));
}

function openMessagesPopover() {
    closeNotificationsPopover();
    const pop = document.getElementById('messagesPopover');
    const btn = document.getElementById('messagesBtn');
    if (!pop) return;
    renderInboxList();
    pop.classList.remove('is-hidden');
    btn?.setAttribute('aria-expanded', 'true');
}

function closeMessagesPopover() {
    const pop = document.getElementById('messagesPopover');
    const btn = document.getElementById('messagesBtn');
    if (pop) pop.classList.add('is-hidden');
    btn?.setAttribute('aria-expanded', 'false');
}

function toggleMessagesPopover(ev) {
    if (ev) ev.stopPropagation();
    if (isMessagesPopoverOpen()) closeMessagesPopover();
    else openMessagesPopover();
}

/** فتح لوحة الوارد (مثلاً من تبويب خاص) — يفتح دائماً وليس تبديلاً */
function openMessagesModal() {
    openMessagesPopover();
}

function closeMessagesModal() {
    closeMessagesPopover();
}

function saveProfile() {
    closeProfileModal();
}

function saveProfileSettings() {
    const nickEl = document.getElementById('userDisplayName');
    if (nickEl) {
        const n = sanitizeNickname(nickEl.value);
        if (n) setSecureItem('nickname', n);
    }
    const genderInput = document.getElementById('userGender');
    if (genderInput) setSecureItem('gender', sanitizeInput(genderInput.value));
    const ageInput = document.getElementById('userAge');
    if (ageInput) {
        let age = parseInt(ageInput.value, 10);
        if (isNaN(age)) age = 18;
        age = Math.min(120, Math.max(1, age));
        setSecureItem('age', String(age));
    }
    const country = document.getElementById('userCountry');
    if (country) setSecureItem('countryCode', country.value);
    const rel = document.getElementById('userRelationship');
    if (rel) setSecureItem('relationship', rel.value);
    const bio = document.getElementById('userBio');
    if (bio) setSecureItem('bio', sanitizeInput(bio.value));

    const privacyImages = document.getElementById('privacyImages');
    const privacyPrivateChat = document.getElementById('privacyPrivateChat');
    const privacyOnlineStatus = document.getElementById('privacyOnlineStatus');
    if (privacyImages) setSecureItem('privacyImages', privacyImages.value);
    if (privacyPrivateChat) setSecureItem('privacyPrivateChat', privacyPrivateChat.value);
    if (privacyOnlineStatus) setSecureItem('privacyOnlineStatus', privacyOnlineStatus.value);

    const ucl = document.getElementById('userChatLang');
    if (ucl) {
        setSecureItem('lang', ucl.value);
        const ls = document.getElementById('langSelect');
        if (ls) ls.value = ucl.value;
    }

    const emailEl = document.getElementById('userEmail');
    if (emailEl && emailEl.value) setSecureItem('userEmail', sanitizeInput(emailEl.value));
    const tzEl = document.getElementById('userTimezone');
    if (tzEl) setSecureItem('userTimezone', tzEl.value);
    const ns = document.getElementById('notifSounds');
    if (ns) setSecureItem('notifSounds', ns.value);
    const nj = document.getElementById('notifJoinLeave');
    if (nj) setSecureItem('notifJoinLeave', nj.value);
    const nt = document.getElementById('notifTheme');
    if (nt) setSecureItem('notifTheme', nt.value);

    if (socket) {
        socket.emit('updatePrivacy', {
            allowPrivateChat: (privacyPrivateChat && privacyPrivateChat.value) === 'on',
            allowPrivateImages: privacyImages ? privacyImages.value : 'everyone'
        });
    }
    closeProfileModal();
    updateTexts(getSecureItem('lang') || 'en');
}

function getCurrentTime() {
    return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function insertRoomMention(username) {
    const input = document.getElementById('msgInput');
    if (!input) return;
    const u = String(username || '').trim();
    if (!u) return;
    // صيغة مرئية داخل النص: @name (استبدل المسافات ب _ لتبقى token واحدة)
    const token = '@' + u.replace(/\s+/g, '_');
    const cur = input.value || '';
    const next = cur && !/\s$/.test(cur) ? (cur + ' ' + token + ' ') : (cur + token + ' ');
    input.value = next;
    input.focus();
    window.__pendingRoomMention = { username: u, token };
}

function applyMentionHighlightIfNeeded(msgDiv, data) {
    const me = getSecureItem('nickname') || 'Guest';
    const mentions = Array.isArray(data?.mentions) ? data.mentions : [];
    if (mentions.some((u) => String(u || '').toLowerCase() === String(me).toLowerCase())) {
        msgDiv.classList.add('mention-hit');
    }
}

function renderTextWithMentionToken(text, token) {
    // إبراز token فقط (بدون innerHTML)
    const s = String(text || '');
    const t = String(token || '');
    if (!t || s.indexOf(t) === -1) {
        // fallback: إبراز أي @word بسيطة
        const m = s.match(/@\S+/g);
        if (!m) {
            const span = document.createElement('span');
            span.textContent = sanitizeInput(s);
            return span;
        }
        const frag = document.createDocumentFragment();
        let rest = s;
        while (true) {
            const mm = rest.match(/@\S+/);
            if (!mm) break;
            const idx = rest.indexOf(mm[0]);
            const before = rest.slice(0, idx);
            if (before) frag.appendChild(document.createTextNode(sanitizeInput(before)));
            const tag = document.createElement('span');
            tag.className = 'mention-token';
            tag.textContent = sanitizeInput(mm[0]);
            frag.appendChild(tag);
            rest = rest.slice(idx + mm[0].length);
        }
        if (rest) frag.appendChild(document.createTextNode(sanitizeInput(rest)));
        const wrap = document.createElement('span');
        wrap.appendChild(frag);
        return wrap;
    }
    const frag = document.createDocumentFragment();
    const parts = s.split(t);
    parts.forEach((p, idx) => {
        if (p) {
            const node = document.createTextNode(sanitizeInput(p));
            frag.appendChild(node);
        }
        if (idx !== parts.length - 1) {
            const m = document.createElement('span');
            m.className = 'mention-token';
            m.textContent = sanitizeInput(t);
            frag.appendChild(m);
        }
    });
    const wrap = document.createElement('span');
    wrap.appendChild(frag);
    return wrap;
}

function emitTyping(isTyping) {
    if (socket && currentRoom) {
        socket.emit('typing', {
            username: getSecureItem('nickname') || 'Guest',
            room: currentRoom,
            isTyping
        });
    }
}

function handleTypingEvent() {
    emitTyping(true);
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => emitTyping(false), 2000);
}

function sendMessage() {
    if (isGuestUser()) {
        addNotification('عفواً لا يمكنك المشاركة العامة، يجب تسجيل حساب أولاً حتي تتمكن من المشاركة في المحادثه الجماعية العامة، انتا الآن زائر بإمكانك استخدام الدردشة الخاصة فقط.!');
        return;
    }
    const input = document.getElementById('msgInput');
    if (!input) return;
    let message = input.value.trim();
    if (message === '') return;
    message = sanitizeInput(message);
    if (message === '') return;
    if (socket) {
        const pendingMention = window.__pendingRoomMention || null;
        const mentions = pendingMention && pendingMention.username ? [pendingMention.username] : [];
        socket.emit('chatMessage', {
            room: currentRoom,
            username: getSecureItem('nickname') || 'Guest',
            text: message,
            type: 'text',
            mentions,
            color: userColor,
            time: getCurrentTime()
        });
        window.__pendingRoomMention = null;
        input.value = '';
        emitTyping(false);
        input.focus();
    }
}

async function handleImageUpload(event) {
    if (isGuestUser()) {
        addNotification('عفواً لا يمكنك المشاركة العامة، يجب تسجيل حساب أولاً حتي تتمكن من المشاركة في المحادثه الجماعية العامة، انتا الآن زائر بإمكانك استخدام الدردشة الخاصة فقط.!');
        event.target.value = '';
        return;
    }
    const file = event.target.files[0];
    if (!file) return;
    if (!isValidImage(file)) {
        alert('Invalid image format. Allowed: JPG, PNG, GIF, WEBP');
        event.target.value = '';
        return;
    }
    if (file.size > 2 * 1024 * 1024) {
        alert('Image too large. Max 2MB');
        event.target.value = '';
        return;
    }
    try {
        const media = await compressImageFileToDataUrl(file, { maxDim: 1400, maxBytes: 1.85 * 1024 * 1024 });
        if (socket) {
            socket.emit('chatMessage', {
                room: currentRoom,
                username: getSecureItem('nickname') || 'Guest',
                media,
                type: 'image',
                color: userColor,
                time: getCurrentTime()
            });
        }
    } catch {
        alert(currentLang() === 'ar' ? 'تعذّر ضغط الصورة' : 'Could not process image');
    }
    event.target.value = '';
}

async function handlePrivateImageUpload(event) {
    const file = event.target.files[0];
    if (!file || !currentPrivatePeer) return;
    if (!isValidImage(file)) {
        alert('Invalid image format');
        event.target.value = '';
        return;
    }
    if (file.size > 2 * 1024 * 1024) {
        alert('Image too large. Max 2MB');
        event.target.value = '';
        return;
    }
    try {
        const media = await compressImageFileToDataUrl(file, { maxDim: 1400, maxBytes: 1.85 * 1024 * 1024 });
        if (socket) {
            socket.emit('privateMessage', {
                toUsername: currentPrivatePeer,
                media,
                type: 'image',
                color: userColor
            });
        }
    } catch {
        alert(currentLang() === 'ar' ? 'تعذّر ضغط الصورة' : 'Could not process image');
    }
    event.target.value = '';
}

function sendPrivateMessage() {
    const input = document.getElementById('privateMsgInput');
    if (!input || !currentPrivatePeer || !socket) return;
    let message = input.value.trim();
    if (message === '') return;
    message = sanitizeInput(message);
    if (message === '') return;
    socket.emit('privateMessage', {
        toUsername: currentPrivatePeer,
        text: message,
        type: 'text',
        color: userColor
    });
    input.value = '';
    input.focus();
}

// =============== Audio recording (room/private) ===============
let mediaRecorder = null;
let mediaChunks = [];
let mediaMode = null; // 'room' | 'private'

async function startAudioRecording(mode) {
    if (!navigator.mediaDevices?.getUserMedia) {
        alert(currentLang() === 'ar' ? 'المتصفح لا يدعم تسجيل الصوت' : 'Audio recording not supported');
        return;
    }
    if (mediaRecorder && mediaRecorder.state === 'recording') return;
    mediaMode = mode;
    mediaChunks = [];
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const options = {};
    try {
        mediaRecorder = new MediaRecorder(stream, options);
    } catch {
        mediaRecorder = new MediaRecorder(stream);
    }
    mediaRecorder.ondataavailable = (e) => {
        if (e.data && e.data.size > 0) mediaChunks.push(e.data);
    };
    mediaRecorder.onstop = () => {
        const blob = new Blob(mediaChunks, { type: mediaRecorder.mimeType || 'audio/webm' });
        stream.getTracks().forEach((t) => t.stop());
        if (blob.size > 2 * 1024 * 1024) {
            alert(currentLang() === 'ar' ? 'الصوت طويل/كبير جداً (الحد 2MB)' : 'Audio too large (max 2MB)');
            return;
        }
        const reader = new FileReader();
        reader.onload = () => {
            const dataUrl = reader.result;
            if (mediaMode === 'room') {
                // العام: نفس قيودك الحالية (الضيف ممنوع في العام)
                if (isGuestUser()) {
                    addNotification('عفواً لا يمكنك المشاركة العامة، يجب تسجيل حساب أولاً حتي تتمكن من المشاركة في المحادثه الجماعية العامة، انتا الآن زائر بإمكانك استخدام الدردشة الخاصة فقط.!');
                    return;
                }
                socket?.emit('chatMessage', {
                    room: currentRoom,
                    type: 'audio',
                    media: dataUrl,
                    color: userColor
                });
            } else if (mediaMode === 'private') {
                if (!currentPrivatePeer) return;
                socket?.emit('privateMessage', {
                    toUsername: currentPrivatePeer,
                    type: 'audio',
                    media: dataUrl,
                    color: userColor
                });
            }
        };
        reader.readAsDataURL(blob);
    };
    mediaRecorder.start();
}

function stopAudioRecording() {
    if (!mediaRecorder || mediaRecorder.state !== 'recording') return;
    mediaRecorder.stop();
}

function ensureThread(peer) {
    if (!privateThreads.has(peer)) {
        privateThreads.set(peer, { messages: [], unread: 0 });
    }
    return privateThreads.get(peer);
}

function appendPrivateLine(container, data, isMine) {
    const div = document.createElement('div');
    div.className = 'msg ' + (isMine ? 'my-msg' : '');
    // header with avatar + name
    const head = document.createElement('div');
    head.className = 'msg-head';
    const avatar = document.createElement('img');
    avatar.className = 'msg-avatar';
    avatar.loading = 'lazy';
    const avatarSrc = data.avatar || (isMine ? getAvatarUrl() : '');
    if (avatarSrc) avatar.src = avatarSrc;
    else avatar.style.display = 'none';
    const avatarFallback = document.createElement('span');
    avatarFallback.className = 'msg-avatar-fallback';
    avatarFallback.textContent = '👤';
    if (avatarSrc) avatarFallback.style.display = 'none';
    const name = document.createElement('span');
    name.className = 'username-tag';
    name.style.color = data.color || '#00d2ff';
    name.textContent = sanitizeInput(isMine ? (getSecureItem('nickname') || 'Guest') : (data.from || ''));
    head.appendChild(avatar);
    head.appendChild(avatarFallback);
    head.appendChild(name);
    if (!isMine) {
        const actions = document.createElement('span');
        actions.className = 'msg-actions';
        const more = document.createElement('button');
        more.type = 'button';
        more.className = 'msg-action-btn';
        more.textContent = '⋯';
        more.title = tKey('ctxReport') || 'Report';
        more.addEventListener('click', (evt) => {
            evt.stopPropagation();
            openUserContextMenu(evt, data.from || '');
        });
        actions.appendChild(more);
        head.appendChild(actions);
    }
    div.appendChild(head);

    if (data.type === 'image' && data.media) {
        const img = document.createElement('img');
        img.src = data.media;
        img.className = 'chat-img chat-media-thumb';
        img.alt = '';
        img.loading = 'lazy';
        bindChatMediaOpen(img);
        div.appendChild(img);
    } else if (data.type === 'gif' && data.media) {
        const img = document.createElement('img');
        img.src = data.media;
        img.className = 'chat-img chat-gif chat-media-thumb';
        img.alt = '';
        img.loading = 'lazy';
        bindChatMediaOpen(img);
        div.appendChild(img);
    } else if (data.type === 'audio' && data.media) {
        const audio = document.createElement('audio');
        audio.controls = true;
        audio.className = 'audio-msg';
        audio.src = data.media;
        div.appendChild(audio);
    } else {
        const span = document.createElement('span');
        span.textContent = sanitizeInput(data.text || '');
        div.appendChild(span);
    }
    const time = document.createElement('span');
    time.className = 'msg-time';
    time.style.cssText = 'font-size:10px;opacity:0.5;margin-left:8px;';
    time.textContent = data.time || getCurrentTime();
    div.appendChild(time);

    // WhatsApp-like ticks for outgoing messages (read vs sent)
    if (data.outgoing) {
        const isRead = data.read === true;
        const status = document.createElement('span');
        status.className = 'pm-read-status';
        status.textContent = isRead ? ' ✓✓' : ' ✓';
        status.style.cssText = isRead
            ? 'font-size:10px;opacity:0.95;margin-left:4px;color:#22c55e;font-weight:800;'
            : 'font-size:10px;opacity:0.35;margin-left:4px;color:rgba(255,255,255,0.9);font-weight:800;';
        div.appendChild(status);
    }
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

function renderPrivateThread(peer) {
    const area = document.getElementById('privateMessagesArea');
    if (!area) return;
    area.innerHTML = '';
    const thread = ensureThread(peer);
    thread.messages.forEach((m) => {
        const me = getSecureItem('nickname') || 'Guest';
        const isMine = m.outgoing || m.from === me;
        appendPrivateLine(area, m, isMine);
    });
}

function renderPrivateThreadsList() {
    const list = document.getElementById('privateThreadsList');
    if (!list) return;
    list.innerHTML = '';
    const searchEl = document.getElementById('privateThreadSearchInput');
    const q = (searchEl?.value || '').trim().toLowerCase();

    const peers = [...privateThreads.keys()].filter((peer) => {
        if (!q) return true;
        return sanitizeInput(peer).toLowerCase().includes(q);
    });

    const sorted = peers.sort((a, b) => {
        const tha = privateThreads.get(a);
        const thb = privateThreads.get(b);
        const lastA = tha?.messages?.length ? tha.messages[tha.messages.length - 1] : null;
        const lastB = thb?.messages?.length ? thb.messages[thb.messages.length - 1] : null;
        const tsA = lastA?.ts || 0;
        const tsB = lastB?.ts || 0;
        return tsB - tsA;
    });

    sorted.forEach((peer) => {
        const th = privateThreads.get(peer);
        const last = th.messages.length ? th.messages[th.messages.length - 1] : null;
        const row = document.createElement('div');
        row.className = 'pm-thread' + (currentPrivatePeer === peer ? ' active' : '');

        const avWrap = document.createElement('div');
        avWrap.className = 'pm-thread-avatar-wrap';

        const av = document.createElement('img');
        av.className = 'pm-thread-avatar-img';
        av.loading = 'lazy';
        const lastAvatar = last?.avatar || '';
        if (lastAvatar) av.src = lastAvatar;
        else av.classList.add('is-hidden');

        const avPh = document.createElement('span');
        avPh.className = 'pm-thread-avatar-fallback';
        const initial = sanitizeInput(peer).charAt(0) || '?';
        avPh.textContent = initial.toUpperCase();
        avPh.style.setProperty('--av-hue', String(avatarHueFromString(peer)));
        if (lastAvatar) avPh.classList.add('is-hidden');

        avWrap.appendChild(av);
        avWrap.appendChild(avPh);

        const center = document.createElement('div');
        center.className = 'pm-thread-body';

        const n = document.createElement('div');
        n.className = 'pm-name';
        n.textContent = sanitizeInput(peer);

        const l = document.createElement('div');
        l.className = 'pm-last';
        l.textContent = !last
            ? ''
            : (last.type === 'image'
                ? '📷'
                : (last.type === 'gif'
                    ? '🎞️'
                    : (last.type === 'audio' ? '🎤' : sanitizeInput(last.text || ''))));

        center.appendChild(n);
        center.appendChild(l);

        const meta = document.createElement('div');
        meta.className = 'pm-meta';

        if (th.unread > 0) {
            const pill = document.createElement('span');
            pill.className = 'pm-unread-pill';
            pill.textContent = String(th.unread);
            meta.appendChild(pill);
        }

        if (last?.time) {
            const tm = document.createElement('span');
            tm.className = 'pm-time';
            tm.textContent = last.time;
            meta.appendChild(tm);
        }

        row.appendChild(avWrap);
        row.appendChild(center);
        row.appendChild(meta);
        row.addEventListener('click', () => startPrivateChat(peer));
        list.appendChild(row);
    });
}

function switchChatView(mode) {
    const roomViewWrap = document.getElementById('roomViewWrap');
    const panePrivate = document.getElementById('panePrivate');
    const tabRoom = document.getElementById('tabRoomView');
    if (mode === 'private') {
        if (roomViewWrap) roomViewWrap.style.display = 'none';
        if (panePrivate) {
            panePrivate.style.display = 'flex';
            panePrivate.style.flexDirection = 'column';
        }
        if (tabRoom) tabRoom.classList.remove('active');
    } else {
        if (roomViewWrap) roomViewWrap.style.display = '';
        if (panePrivate) panePrivate.style.display = 'none';
        if (tabRoom) tabRoom.classList.add('active');
    }
}

function startPrivateChat(username) {
    const me = getSecureItem('nickname') || 'Guest';
    if (!username || username === me) return;
    if (isBlockedUser(username)) {
        showReportToast(tKey('blockedDone') || 'User blocked.');
        return;
    }
    currentPrivatePeer = username;
    const label = document.getElementById('privatePeerLabel');
    if (label) label.textContent = sanitizeInput(username);
    updatePrivateChatHeader(username);
    renderPrivateThread(username);
    renderPrivateThreadsList();
    switchChatView('private');
    const t = ensureThread(username);

    // When opening the chat, mark the latest incoming message as "read"
    // to show ✓✓ (WhatsApp-like).
    try {
        const panePrivate = document.getElementById('panePrivate');
        const paneVisible = panePrivate && panePrivate.style.display !== 'none';
        if (paneVisible) {
            const lastIncoming = Array.isArray(t.messages)
                ? [...t.messages].reverse().find((m) => !m.outgoing && m.from === username && m.messageId)
                : null;
            if (lastIncoming?.messageId && !privateSeenAcked.has(lastIncoming.messageId)) {
                privateSeenAcked.add(lastIncoming.messageId);
                const delay = 720 + Math.floor(Math.random() * 320);
                setTimeout(() => {
                    try {
                        if (socket && currentPrivatePeer === username) {
                            socket.emit('privateMessageSeen', { messageId: lastIncoming.messageId });
                        }
                    } catch {
                        /* ignore */
                    }
                }, delay);
            }
        }
    } catch {
        /* ignore */
    }

    t.unread = 0;
    updateInboxBadge();
}

function updateInboxBadge() {
    let n = 0;
    privateThreads.forEach((th) => {
        n += th.unread || 0;
    });
    const badge = document.querySelector('#messagesBtn .badge');
    if (badge) {
        badge.textContent = n > 0 ? String(n) : '';
        badge.style.display = n > 0 ? 'inline-block' : 'none';
    }
}

function renderInboxList() {
    const list = document.getElementById('inboxList');
    const empty = document.getElementById('t-inboxEmpty');
    if (!list) return;
    list.innerHTML = '';
    if (privateThreads.size === 0) {
        if (empty) empty.style.display = 'block';
        return;
    }
    if (empty) empty.style.display = 'none';
    const peers = [...privateThreads.keys()].sort();
    peers.forEach((peer) => {
        const th = privateThreads.get(peer);
        const last = th.messages.length ? th.messages[th.messages.length - 1] : null;
        const row = document.createElement('div');
        row.className = 'inbox-row messenger-inbox-row';
        const ini = sanitizeInput(peer).charAt(0) || '?';
        const avWrap = document.createElement('div');
        avWrap.className = 'inbox-avatar-wrap';
        const avImg = document.createElement('img');
        avImg.className = 'inbox-avatar-img';
        avImg.alt = '';
        avImg.loading = 'lazy';
        const lastAvatar = last?.avatar || '';
        if (lastAvatar) avImg.src = lastAvatar;
        else avImg.classList.add('is-hidden');
        const avPh = document.createElement('span');
        avPh.className = 'inbox-avatar-fallback';
        avPh.textContent = ini.toUpperCase();
        avPh.style.setProperty('--av-hue', String(avatarHueFromString(peer)));
        if (lastAvatar) avPh.classList.add('is-hidden');
        avWrap.appendChild(avImg);
        avWrap.appendChild(avPh);
        const left = document.createElement('div');
        left.className = 'inbox-row-main';
        const name = document.createElement('div');
        name.className = 'inbox-row-name';
        name.textContent = sanitizeInput(peer);
        left.appendChild(name);
        if (last) {
            const prev = document.createElement('div');
            prev.className = 'inbox-preview';
            prev.textContent =
                last.type === 'image'
                    ? '📷'
                    : (last.type === 'gif'
                        ? '🎞️'
                        : (last.type === 'audio' ? '🎤' : sanitizeInput(last.text || '')));
            left.appendChild(prev);
        }
        row.appendChild(avWrap);
        row.appendChild(left);
        if (th.unread > 0) {
            const dot = document.createElement('span');
            dot.className = 'unread-dot';
            row.appendChild(dot);
        }
        row.addEventListener('click', () => {
            startPrivateChat(peer);
            closeMessagesModal();
            const ci = document.getElementById('chatInterface');
            if (ci && window.getComputedStyle(ci).display !== 'none') switchChatView('private');
        });
        list.appendChild(row);
    });
}

function joinRoom(el) {
    if (!el || !el.getAttribute) return;
    const room = el.getAttribute('data-room');
    if (!room) return;
    const titleEl = el.querySelector('h3');
    const displayTitle = titleEl ? titleEl.textContent.trim() : room;

    const prevRoom = currentRoom || '';
    const crn = document.getElementById('currentRoomName');
    const prevTitle = (crn && crn.textContent) ? crn.textContent.trim() : prevRoom;
    joinDeniedRecovery = { room: prevRoom, title: prevTitle || prevRoom };

    currentRoom = room;
    const roomSelection = document.getElementById('roomSelection');
    const chatInterface = document.getElementById('chatInterface');
    const currentRoomName = document.getElementById('currentRoomName');

    if (roomSelection) roomSelection.style.display = 'none';
    if (chatInterface) {
        chatInterface.style.display = 'flex';
        chatInterface.style.flexDirection = 'column';
    }
    if (currentRoomName) currentRoomName.textContent = displayTitle;
    document.body.classList.add('in-room');
    syncRandomFabVisibility();

    switchChatView('room');
    currentPrivatePeer = null;
    if (isGuestUser() && !guestNoticePushed) {
        guestNoticePushed = true;
        addNotification('عفواً لا يمكنك المشاركة العامة، يجب تسجيل حساب أولاً حتي تتمكن من المشاركة في المحادثه الجماعية العامة، انتا الآن زائر بإمكانك استخدام الدردشة الخاصة فقط.!');
    }

    const allowPrivateChat = (getSecureItem('privacyPrivateChat') || 'on') === 'on';
    const allowPrivateImages = getSecureItem('privacyImages') || 'everyone';
    const avatar = getAvatarUrl();
    const coverPhoto = getCoverUrl();

    if (socket) {
        socket.emit('joinRoom', {
            username: getSecureItem('nickname') || 'Guest',
            room: currentRoom,
            gender: getSecureItem('gender') || 'male',
            allowPrivateChat,
            allowPrivateImages,
            avatar,
            coverPhoto
        });
    }
}

function leaveRoom() {
    if (socket) socket.emit('leaveRoom');
    currentRoom = '';
    const roomSelection = document.getElementById('roomSelection');
    const chatInterface = document.getElementById('chatInterface');
    const messagesArea = document.getElementById('messagesArea');
    const privateArea = document.getElementById('privateMessagesArea');
    if (roomSelection) roomSelection.style.display = 'block';
    if (chatInterface) chatInterface.style.display = 'none';
    if (messagesArea) messagesArea.innerHTML = '';
    if (privateArea) privateArea.innerHTML = '';
    document.body.classList.remove('in-room');
    syncRandomFabVisibility();
    hideEmojiPicker();
    hideGifPicker();
    closeUserContextMenu();
}

document.addEventListener('DOMContentLoaded', async () => {
    const path0 = window.location.pathname || '';
    const onLanding =
        path0 === '/' || path0 === '' || path0.endsWith('index.html') || path0.endsWith('/index.html');
    if (onLanding) {
        const oerr = new URLSearchParams(window.location.search).get('oauth_err');
        if (oerr) {
            alert(messageForOauthErr(oerr));
            try {
                const u = new URL(window.location.href);
                u.searchParams.delete('oauth_err');
                const qs = u.searchParams.toString();
                history.replaceState({}, '', u.pathname + (qs ? `?${qs}` : '') + u.hash);
            } catch {
                /* ignore */
            }
        }
    }
    await syncMemberSessionFromCookie();
    if (getSecureItem('authType') === 'member') {
        try {
            const r = await secureFetch('/api/auth/verify');
            let data = {};
            try {
                data = await r.json();
            } catch {
                /* ignore */
            }
            if (r.status === 403 && data.code === 'account_banned') {
                try {
                    await secureFetch('/api/auth/logout', { method: 'POST' });
                } catch {
                    /* ignore */
                }
                localStorage.removeItem('authType');
                localStorage.removeItem('nickname');
                localStorage.removeItem('gender');
                const loc = currentLang() === 'ar' ? 'ar' : 'en';
                const until = data.bannedUntil ? new Date(data.bannedUntil).toLocaleString(loc) : '';
                alert(
                    currentLang() === 'ar'
                        ? `حسابك محظور مؤقتاً${until ? ` حتى ${until}` : ''}.`
                        : `Your account is temporarily banned${until ? ` until ${until}` : ''}.`
                );
                if (window.location.pathname.includes('rooms.html')) {
                    window.location.href = 'index.html';
                    return;
                }
            }
            if (r.status === 401 && data.code === 'session_revoked') {
                try {
                    await secureFetch('/api/auth/logout', { method: 'POST' });
                } catch {
                    /* ignore */
                }
                localStorage.removeItem('authType');
                localStorage.removeItem('nickname');
                localStorage.removeItem('gender');
                alert(tKey('sessionRevoked'));
                if (window.location.pathname.includes('rooms.html')) {
                    window.location.href = 'index.html';
                    return;
                }
            }
        } catch {
            /* ignore */
        }
    }

    const savedLang = getSecureItem('lang') || 'en';
    const savedTheme = getSecureItem('theme') || 'dark';

    if (savedTheme === 'light') document.body.classList.add('light');
    try {
        updateTexts(savedLang);
        initRoomCards();
        syncEmojiPickerTheme();
    } catch (err) {
        console.error('init UI error:', err);
    }

    document.getElementById('privateThreadSearchInput')?.addEventListener('input', () => {
        renderPrivateThreadsList();
    });

    document.getElementById('sidebarUserSearch')?.addEventListener('input', filterSidebarUsers);

    ensureEmojiPopoverBuilt();
    ensureGifPopoverBuilt();
    document.getElementById('userGender')?.addEventListener('change', syncGenderSelectStyle);
    document.getElementById('regGenderInput')?.addEventListener('change', syncGenderSelectStyle);
    syncGenderSelectStyle();
    wireRandomMatchUI();
    syncRandomFabVisibility();
    document.getElementById('emojiBtnRoom')?.addEventListener('click', (e) => toggleEmojiPicker(e, 'room'));
    document.getElementById('emojiBtnPrivate')?.addEventListener('click', (e) => toggleEmojiPicker(e, 'private'));
    document.getElementById('gifBtnRoom')?.addEventListener('click', (e) => toggleGifPicker(e, 'room'));
    document.getElementById('gifBtnPrivate')?.addEventListener('click', (e) => toggleGifPicker(e, 'private'));

    const langSelect = document.getElementById('langSelect');
    if (langSelect) {
        langSelect.value = savedLang;
        langSelect.addEventListener('change', (e) => {
            setSecureItem('lang', e.target.value);
            updateTexts(e.target.value);
        });
    }

    const themeBtn = document.getElementById('themeToggle');
    if (themeBtn) {
        themeBtn.innerText = savedTheme === 'light' ? '☀️' : '🌙';
        themeBtn.addEventListener('click', toggleTheme);
    }

    const settingsBtn = document.getElementById('settingsBtn');
    const myDropdown = document.getElementById('myDropdown');
    if (settingsBtn && myDropdown) {
        settingsBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            myDropdown.classList.toggle('show');
        });
    }
    window.addEventListener('click', () => {
        if (myDropdown) myDropdown.classList.remove('show');
        closeUserContextMenu();
    });

    const openProfile = document.getElementById('openProfileLink');
    if (openProfile) {
        openProfile.addEventListener('click', (e) => {
            e.preventDefault();
            openProfileModal();
        });
    }

    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            try {
                await secureFetch('/api/auth/logout', { method: 'POST' });
            } catch {
                // ignore network errors; fallback page navigation still happens
            } finally {
                localStorage.removeItem('authType');
                localStorage.removeItem('nickname');
                localStorage.removeItem('gender');
            }
        });
    }

    document.getElementById('logoutAllDevicesBtn')?.addEventListener('click', async (e) => {
        e.preventDefault();
        if (getSecureItem('authType') !== 'member') {
            alert(currentLang() === 'ar' ? 'خاصة بالحسابات المسجّلة' : 'Members only');
            return;
        }
        const ok = window.confirm(
            currentLang() === 'ar'
                ? 'سيتم تسجيل خروجك من جميع الأجهزة. المتابعة؟'
                : 'You will be signed out everywhere. Continue?'
        );
        if (!ok) return;
        try {
            const r = await secureFetch('/api/auth/logout-all', { method: 'POST' });
            if (!r.ok) {
                alert(currentLang() === 'ar' ? 'تعذّر تنفيذ الطلب' : 'Request failed');
                return;
            }
        } catch {
            alert(currentLang() === 'ar' ? 'خطأ في الاتصال' : 'Network error');
            return;
        }
        localStorage.removeItem('authType');
        localStorage.removeItem('nickname');
        localStorage.removeItem('gender');
        window.location.href = 'index.html';
    });

    document.getElementById('userAvatarBtn')?.addEventListener('click', openProfileModal);
    document.getElementById('avatarPickBtn')?.addEventListener('click', () => document.getElementById('avatarInput')?.click());
    document.getElementById('avatarInput')?.addEventListener('change', handleAvatarFile);
    document.getElementById('coverPickBtn')?.addEventListener('click', () => document.getElementById('coverInput')?.click());
    document.getElementById('coverInput')?.addEventListener('change', handleCoverFile);
    document.getElementById('mediaLightboxClose')?.addEventListener('click', closeMediaLightbox);
    document.getElementById('mediaLightboxBackdrop')?.addEventListener('click', closeMediaLightbox);
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeMediaLightbox();
    });

    document.getElementById('messagesBtn')?.addEventListener('click', toggleMessagesPopover);
    document.getElementById('notificationsBtn')?.addEventListener('click', toggleNotificationsPopover);
    document.getElementById('closeNotificationsPopover')?.addEventListener('click', (e) => {
        e.stopPropagation();
        closeNotificationsPopover();
    });
    document.getElementById('closeMessagesPopover')?.addEventListener('click', (e) => {
        e.stopPropagation();
        closeMessagesPopover();
    });

    document.addEventListener('click', (e) => {
        const t = e.target;
        if (t && t.closest && t.closest('#emojiPopover')) return;
        if (t && t.closest && t.closest('#gifPopover')) return;
        if (t && t.closest && t.closest('.emoji-btn')) return;
        if (t && t.closest && t.closest('.gif-btn')) return;
        const msgA = document.getElementById('messagesPopoverAnchor');
        if (isMessagesPopoverOpen() && msgA && !msgA.contains(t)) closeMessagesPopover();
        const notifA = document.getElementById('notificationsPopoverAnchor');
        if (isNotificationsPopoverOpen() && notifA && !notifA.contains(t)) closeNotificationsPopover();
        hideEmojiPicker();
        hideGifPicker();
    });
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape') return;
        if (isMessagesPopoverOpen()) closeMessagesPopover();
        if (isNotificationsPopoverOpen()) closeNotificationsPopover();
        hideEmojiPicker();
        hideGifPicker();
    });
    document.getElementById('closeProfileModal')?.addEventListener('click', closeProfileModal);
    document.getElementById('closeProfileModalAlt')?.addEventListener('click', closeProfileModal);
    document.getElementById('saveProfileSettingsBtn')?.addEventListener('click', saveProfileSettings);
    document.getElementById('profileModal')?.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter') return;
        const el = e.target;
        if (!el || el.tagName === 'TEXTAREA' || el.tagName === 'BUTTON') return;
        if (el.tagName === 'SELECT') return;
        e.preventDefault();
        document.getElementById('saveProfileSettingsBtn')?.click();
    });
    document.getElementById('leaveRoomBtn')?.addEventListener('click', leaveRoom);
    document.getElementById('ctxPrivateBtn')?.addEventListener('click', () => {
        if (contextTargetUser) startPrivateChat(contextTargetUser);
        closeUserContextMenu();
    });
    document.getElementById('ctxProfileBtn')?.addEventListener('click', () => {
        if (contextTargetUser) {
            openProfileModal();
            const field = document.getElementById('userDisplayName');
            if (field) field.value = contextTargetUser;
        }
        closeUserContextMenu();
    });
    document.getElementById('ctxReportBtn')?.addEventListener('click', () => {
        if (contextTargetUser) openReportModal(contextTargetUser);
        closeUserContextMenu();
    });
    document.getElementById('ctxBlockBtn')?.addEventListener('click', () => {
        if (contextTargetUser) openBlockConfirmModal(contextTargetUser);
        closeUserContextMenu();
    });

    document.getElementById('closeReportModal')?.addEventListener('click', () => closeModalEl(document.getElementById('reportModal')));
    document.getElementById('cancelReportBtn')?.addEventListener('click', () => closeModalEl(document.getElementById('reportModal')));
    document.getElementById('submitReportBtn')?.addEventListener('click', () => {
        const me = getSecureItem('nickname') || 'Guest';
        const reason = String(document.getElementById('reportReasonSelect')?.value || 'other');
        const details = sanitizeInput(document.getElementById('reportDetailsInput')?.value || '').slice(0, 400);
        const payload = {
            reporter: me,
            reportedUser: moderationTargetUser,
            reason,
            details,
            room: currentRoom || '',
            status: 'pending_review',
            createdAt: new Date().toISOString()
        };
        saveReportLocal(payload);
        closeModalEl(document.getElementById('reportModal'));
        showReportToast(tKey('reportSentToast') || 'Report sent, thank you');
    });

    document.getElementById('closeBlockModal')?.addEventListener('click', () => closeModalEl(document.getElementById('blockConfirmModal')));
    document.getElementById('cancelBlockBtn')?.addEventListener('click', () => closeModalEl(document.getElementById('blockConfirmModal')));
    document.getElementById('confirmBlockBtn')?.addEventListener('click', () => {
        if (!moderationTargetUser) return;
        blockUserLocal(moderationTargetUser);
        closeModalEl(document.getElementById('blockConfirmModal'));
        if (currentPrivatePeer && isBlockedUser(currentPrivatePeer)) {
            currentPrivatePeer = null;
            const area = document.getElementById('privateMessagesArea');
            if (area) area.innerHTML = '';
        }
        showReportToast(tKey('blockedDone') || 'User blocked.');
    });

    document.getElementById('tabRoomView')?.addEventListener('click', () => switchChatView('room'));

    document.getElementById('roomsGrid')?.addEventListener('click', (e) => {
        const card = e.target.closest('.room-card');
        if (card) joinRoom(card);
    });

    const msgInput = document.getElementById('msgInput');
    if (msgInput) {
        msgInput.addEventListener('input', handleTypingEvent);
        msgInput.addEventListener('keydown', (e) => {
            if (e.key !== 'Enter' || e.shiftKey) return;
            e.preventDefault();
            sendMessage();
        });
    }
    document.getElementById('sendBtn')?.addEventListener('click', sendMessage);
    document.getElementById('camBtn')?.addEventListener('click', () => document.getElementById('imageInput')?.click());
    document.getElementById('imageInput')?.addEventListener('change', handleImageUpload);
    document.getElementById('micBtn')?.addEventListener('click', async () => {
        if (mediaRecorder && mediaRecorder.state === 'recording') stopAudioRecording();
        else await startAudioRecording('room');
    });

    document.getElementById('privateSendBtn')?.addEventListener('click', sendPrivateMessage);
    document.getElementById('privateMsgInput')?.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter' || e.shiftKey) return;
        e.preventDefault();
        sendPrivateMessage();
    });
    document.getElementById('privateCamBtn')?.addEventListener('click', () => document.getElementById('privateImageInput')?.click());
    document.getElementById('privateImageInput')?.addEventListener('change', handlePrivateImageUpload);
    document.getElementById('privateMicBtn')?.addEventListener('click', async () => {
        if (mediaRecorder && mediaRecorder.state === 'recording') stopAudioRecording();
        else await startAudioRecording('private');
    });

    document.getElementById('googleBtn')?.addEventListener('click', () => {
        const cid = (window.__GOOGLE_CLIENT_ID__ || '').trim();
        if (!cid) {
            alert(tKey('googleDisabled'));
            return;
        }
        const apiBase = String(window.__API_PUBLIC_URL__ || '').replace(/\/$/, '');
        const q = `return=${encodeURIComponent('/rooms.html')}`;
        const startPath = `/api/auth/google/start?${q}`;
        location.href = apiBase ? `${apiBase}${startPath}` : startPath;
    });

    document.getElementById('guestBtn')?.addEventListener('click', () => {
        openModal(document.getElementById('nickModal'));
    });

    const memberBtn = document.getElementById('memberBtn');
    const memberModal = document.getElementById('memberModal');
    const closeMemberModal = document.getElementById('closeMemberModal');
    const confirmMemberLogin = document.getElementById('confirmMemberLogin');
    const memberErrorMsg = document.getElementById('memberErrorMsg');
    const memberUsernameInput = document.getElementById('memberUsernameInput');
    const memberPasswordInput = document.getElementById('memberPasswordInput');

    if (memberBtn && memberModal) {
        memberBtn.addEventListener('click', () => {
            openModal(memberModal);
            if (memberErrorMsg) memberErrorMsg.style.display = 'none';
            if (memberUsernameInput) memberUsernameInput.focus();
        });
    }
    if (closeMemberModal && memberModal) {
        closeMemberModal.addEventListener('click', () => {
            closeModalEl(memberModal);
        });
    }
    // ✅ تسجيل الدخول عبر API حقيقي
    if (confirmMemberLogin) {
        confirmMemberLogin.addEventListener('click', async () => {
            const username = sanitizeInput(memberUsernameInput?.value || '').trim();
            const password = memberPasswordInput?.value || '';
            if (!username || !password) {
                if (memberErrorMsg) { memberErrorMsg.innerText = 'أدخل الاسم وكلمة المرور'; memberErrorMsg.style.display = 'block'; }
                return;
            }
            confirmMemberLogin.disabled = true;
            confirmMemberLogin.textContent = '...';
            try {
                const res = await secureFetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await res.json();
                if (!res.ok) {
                    if (memberErrorMsg) {
                        if (data.code === 'account_banned' && data.bannedUntil) {
                            const loc = currentLang() === 'ar' ? 'ar' : 'en';
                            const until = new Date(data.bannedUntil).toLocaleString(loc);
                            memberErrorMsg.innerText =
                                currentLang() === 'ar'
                                    ? `حسابك محظور مؤقتاً حتى ${until}`
                                    : `Account banned until ${until}`;
                        } else if (data.code === 'email_not_verified') {
                            memberErrorMsg.innerText = tKey('emailNotVerified');
                        } else {
                            memberErrorMsg.innerText = data.error || tKey('memberInvalid');
                        }
                        memberErrorMsg.style.display = 'block';
                    }
                    return;
                }
                // التوكن يُحفَظ في HttpOnly Cookie من السيرفر
                setSecureItem('authType', 'member');
                setSecureItem('nickname', data.user.username);
                if (data.user.gender) setSecureItem('gender', data.user.gender);
                closeModalEl(memberModal);
                window.location.href = 'rooms.html';
            } catch {
                if (memberErrorMsg) { memberErrorMsg.innerText = 'خطأ في الاتصال بالسيرفر'; memberErrorMsg.style.display = 'block'; }
            } finally {
                confirmMemberLogin.disabled = false;
                confirmMemberLogin.textContent = tKey('memberLoginBtn') || 'Login';
            }
        });
    }
    memberUsernameInput?.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter') return;
        e.preventDefault();
        memberPasswordInput?.focus();
    });
    memberPasswordInput?.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter') return;
        e.preventDefault();
        confirmMemberLogin?.click();
    });

    // ✅ زر التسجيل (إضافة حساب جديد)
    const registerBtn = document.getElementById('registerBtn');
    const regModal    = document.getElementById('registerModal');
    const closeRegModal = document.getElementById('closeRegModal');
    const confirmReg  = document.getElementById('confirmRegister');
    const regErrorMsg = document.getElementById('regErrorMsg');

    if (registerBtn && regModal) {
        registerBtn.addEventListener('click', () => { openModal(regModal); });
    }
    if (closeRegModal && regModal) {
        closeRegModal.addEventListener('click', () => { closeModalEl(regModal); });
    }
    if (confirmReg) {
        confirmReg.addEventListener('click', async () => {
            const username = sanitizeInput(document.getElementById('regUsernameInput')?.value || '').trim();
            const email = sanitizeInput(document.getElementById('regEmailInput')?.value || '').trim();
            const password = document.getElementById('regPasswordInput')?.value || '';
            const gender   = document.getElementById('regGenderInput')?.value || 'male';
            if (!username || username.length < 3) {
                if (regErrorMsg) {
                    regErrorMsg.innerText = 'الاسم يجب أن يكون 3 أحرف على الأقل';
                    regErrorMsg.classList.remove('is-hidden');
                    regErrorMsg.style.display = 'block';
                }
                return;
            }
            if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
                if (regErrorMsg) {
                    regErrorMsg.innerText = 'أدخل بريد إلكتروني صحيح';
                    regErrorMsg.classList.remove('is-hidden');
                    regErrorMsg.style.display = 'block';
                }
                return;
            }
            if (!password || password.length < 6) {
                if (regErrorMsg) {
                    regErrorMsg.innerText = 'كلمة المرور يجب أن تكون 6 أحرف على الأقل';
                    regErrorMsg.classList.remove('is-hidden');
                    regErrorMsg.style.display = 'block';
                }
                return;
            }
            confirmReg.disabled = true;
            confirmReg.textContent = '...';
            try {
                const res = await secureFetch('/api/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, email, password, gender })
                });
                const data = await res.json();
                if (!res.ok) {
                    if (regErrorMsg) {
                        regErrorMsg.innerText = data.error || 'خطأ في التسجيل';
                        regErrorMsg.classList.remove('is-hidden');
                        regErrorMsg.style.display = 'block';
                    }
                    return;
                }
                // التوكن يُحفَظ في HttpOnly Cookie من السيرفر
                setSecureItem('authType', 'member');
                setSecureItem('nickname', data.user.username);
                if (data.user.gender) setSecureItem('gender', data.user.gender);
                if (data.user.email) setSecureItem('userEmail', data.user.email);
                closeModalEl(regModal);
                if (data.emailPreviewUrl) {
                    alert((currentLang() === 'ar'
                        ? 'تم إرسال رابط التأكيد إلى بريدك. (معاينة التطوير):\n'
                        : 'Verification link sent. (Dev preview):\n') + data.emailPreviewUrl);
                } else {
                    alert(currentLang() === 'ar'
                        ? 'تم إرسال رابط التأكيد إلى بريدك.'
                        : 'Verification link sent to your email.');
                }
                window.location.href = 'rooms.html';
            } catch {
                if (regErrorMsg) {
                    regErrorMsg.innerText = 'خطأ في الاتصال بالسيرفر';
                    regErrorMsg.classList.remove('is-hidden');
                    regErrorMsg.style.display = 'block';
                }
            } finally {
                confirmReg.disabled = false;
                confirmReg.textContent = 'إنشاء حساب';
            }
        });
    }
    document.getElementById('regUsernameInput')?.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter') return;
        e.preventDefault();
        document.getElementById('regPasswordInput')?.focus();
    });
    document.getElementById('regPasswordInput')?.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter') return;
        e.preventDefault();
        document.getElementById('confirmRegister')?.click();
    });

    const closeModal = document.getElementById('closeModal');
    if (closeModal) {
        closeModal.addEventListener('click', () => {
            closeModalEl(document.getElementById('nickModal'));
        });
    }

    const confirmNick = document.getElementById('confirmNick');
    const errorMsgDiv = document.getElementById('nickErrorMsg');
    document.getElementById('nicknameInput')?.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter') return;
        e.preventDefault();
        document.getElementById('confirmNick')?.click();
    });

    if (confirmNick) {
        confirmNick.addEventListener('click', () => {
            let nick = document.getElementById('nicknameInput').value.trim();
            nick = sanitizeNickname(nick);
            if (!nick) {
                if (errorMsgDiv) {
                    errorMsgDiv.innerText = currentLang() === 'ar' ? 'الرجاء إدخال اسم مستعار صالح' : 'Please enter a valid nickname';
                    errorMsgDiv.style.display = 'block';
                }
                return;
            }
            if (errorMsgDiv) errorMsgDiv.style.display = 'none';
            if (socket) {
                socket.emit('checkNickname', nick, (isAvailable) => {
                    if (isAvailable) {
                        setSecureItem('authType', 'guest');
                        setSecureItem('nickname', nick);
                        window.location.href = 'rooms.html';
                    } else if (errorMsgDiv) {
                        errorMsgDiv.innerText = currentLang() === 'ar' ? 'هذا الاسم موجود مسبقاً' : 'This nickname is already taken';
                        errorMsgDiv.style.display = 'block';
                    }
                });
            } else {
                setSecureItem('authType', 'guest');
                setSecureItem('nickname', nick);
                window.location.href = 'rooms.html';
            }
        });
    }

    const displayNick = document.getElementById('displayNick');
    if (displayNick) displayNick.innerText = sanitizeInput(getSecureItem('nickname') || 'Guest');
    if (!getSecureItem('authType')) setSecureItem('authType', 'guest');
    renderNotifications();
    updateNotificationBadge();

    document.querySelectorAll('.profile-tabs .tab-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
            const tab = btn.getAttribute('data-tab');
            document.querySelectorAll('.profile-tabs .tab-btn').forEach((b) => b.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.profile-tab').forEach((p) => {
                p.classList.toggle('active', p.id === 'tab-' + tab);
                p.style.display = p.id === 'tab-' + tab ? 'block' : 'none';
            });
        });
    });
});

if (socket) {
    socket.on('connect_error', async (err) => {
        const msg = String(err?.message || '');
        if (msg.indexOf('SESSION_REVOKED') !== -1) {
            try {
                await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
            } catch {
                /* ignore */
            }
            localStorage.removeItem('authType');
            localStorage.removeItem('nickname');
            localStorage.removeItem('gender');
            alert(tKey('sessionRevoked'));
            if (window.location.pathname.includes('rooms.html')) {
                window.location.href = 'index.html';
            }
            return;
        }
        if (msg.indexOf('ACCOUNT_BANNED') === -1) return;
        try {
            await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
        } catch {
            /* ignore */
        }
        localStorage.removeItem('authType');
        localStorage.removeItem('nickname');
        localStorage.removeItem('gender');
        alert(
            currentLang() === 'ar'
                ? 'حسابك محظور مؤقتاً. تم تسجيل خروجك.'
                : 'Your account is temporarily banned. You have been logged out.'
        );
        if (window.location.pathname.includes('rooms.html')) {
            window.location.href = 'index.html';
        }
    });

    socket.on('message', (data) => {
        const messagesArea = document.getElementById('messagesArea');
        if (!messagesArea) return;
        if (!data.isSystem && data.username && isBlockedUser(data.username)) return;

        const div = document.createElement('div');
        const currentNick = getSecureItem('nickname') || 'Guest';
        div.className = 'msg ' + (data.username === currentNick ? 'my-msg' : '');
        applyMentionHighlightIfNeeded(div, data);

        if (data.isSystem) {
            div.classList.add('system-msg');
            const sysSpan = document.createElement('span');
            sysSpan.textContent = sanitizeInput(data.text);
            sysSpan.style.color = data.color || '#00d2ff';
            div.appendChild(sysSpan);
        } else {
            const head = document.createElement('div');
            head.className = 'msg-head';
            const avatar = document.createElement('img');
            avatar.className = 'msg-avatar';
            avatar.loading = 'lazy';
            const own = data.username === currentNick;
            const avatarSrc = data.avatar || (own ? getAvatarUrl() : '');
            if (avatarSrc) {
                avatar.src = avatarSrc;
            } else {
                avatar.style.display = 'none';
            }
            const avatarFallback = document.createElement('span');
            avatarFallback.className = 'msg-avatar-fallback';
            avatarFallback.textContent = '👤';
            if (avatarSrc) avatarFallback.style.display = 'none';
            head.appendChild(avatar);
            head.appendChild(avatarFallback);

            const userTag = document.createElement('span');
            userTag.className = 'username-tag';
            userTag.style.color = data.color;
            userTag.textContent = sanitizeInput(data.username);
            head.appendChild(userTag);
            if (data.username !== currentNick) {
                userTag.style.cursor = 'pointer';
                userTag.title = currentLang() === 'ar' ? 'إشارة لهذا المستخدم' : 'Mention this user';
                userTag.addEventListener('click', (evt) => {
                    evt.stopPropagation();
                    insertRoomMention(data.username);
                });
            }
            if (!own) {
                const actions = document.createElement('span');
                actions.className = 'msg-actions';
                const more = document.createElement('button');
                more.type = 'button';
                more.className = 'msg-action-btn';
                more.textContent = '⋯';
                more.title = tKey('ctxReport') || 'Report';
                more.addEventListener('click', (evt) => {
                    evt.stopPropagation();
                    openUserContextMenu(evt, data.username);
                });
                actions.appendChild(more);
                head.appendChild(actions);
            }
            div.appendChild(head);

            const timeSpan = document.createElement('span');
            timeSpan.className = 'msg-time';
            timeSpan.style.cssText = 'font-size: 10px; opacity: 0.5; margin-left: 8px;';
            timeSpan.textContent = data.time || getCurrentTime();
            userTag.appendChild(timeSpan);

            if (data.type === 'text') {
                const token = window.__pendingRoomMention?.token || '';
                const node = renderTextWithMentionToken(data.text, token);
                div.appendChild(node);
            } else if (data.type === 'image') {
                const img = document.createElement('img');
                img.src = data.media;
                img.className = 'chat-img chat-media-thumb';
                img.alt = 'Image';
                img.loading = 'lazy';
                bindChatMediaOpen(img);
                div.appendChild(img);
            } else if (data.type === 'gif') {
                const img = document.createElement('img');
                img.src = data.media;
                img.className = 'chat-img chat-gif chat-media-thumb';
                img.alt = 'GIF';
                img.loading = 'lazy';
                bindChatMediaOpen(img);
                div.appendChild(img);
            } else if (data.type === 'audio') {
                const audio = document.createElement('audio');
                audio.controls = true;
                audio.className = 'audio-msg';
                audio.src = data.media;
                div.appendChild(audio);
            }
            rememberPeerFromListUser({
                username: data.username,
                avatar: data.avatar,
                coverPhoto: data.coverPhoto
            });
        }
        messagesArea.appendChild(div);
        messagesArea.scrollTop = messagesArea.scrollHeight;
        if (!data.isSystem && data.username !== currentNick) {
            alertSound.play().catch(() => {});
        }
    });

    socket.on('privateMessage', (data) => {
        const me = getSecureItem('nickname') || 'Guest';
        if (!data.outgoing && data.from && isBlockedUser(data.from)) return;
        const peer = data.outgoing ? data.to : data.from;
        if (!peer) return;
        const thread = ensureThread(peer);
        thread.messages.push({
            from: data.from,
            to: data.to,
            text: data.text,
            media: data.media,
            type: data.type || 'text',
            time: data.time || getCurrentTime(),
            ts: Date.now(),
            outgoing: data.outgoing,
            messageId: data.messageId || null,
            read: data.read === true,
            avatar: data.avatar || null,
            coverPhoto: data.coverPhoto || null,
            color: data.color || '#00d2ff'
        });
        if (!data.outgoing && data.from) {
            rememberPeerFromListUser({
                username: data.from,
                avatar: data.avatar,
                coverPhoto: data.coverPhoto
            });
            if (currentPrivatePeer && data.from === currentPrivatePeer) {
                updatePrivateChatHeader(currentPrivatePeer);
            }
        }
        const active = currentPrivatePeer === peer;
        if (!active && !data.outgoing) thread.unread = (thread.unread || 0) + 1;
        else if (!data.outgoing) thread.unread = 0;
        updateInboxBadge();
        renderPrivateThreadsList();

        if (active) {
            const area = document.getElementById('privateMessagesArea');
            if (area) {
                const isMine = data.outgoing || data.from === me;
                appendPrivateLine(area, data, isMine);

                // Mark as read (WhatsApp-like) when the active thread receives a new incoming message
                if (!data.outgoing && data.messageId) {
                    const pane = document.getElementById('panePrivate');
                    const paneVisible = pane && pane.style.display !== 'none';
                    if (paneVisible && currentPrivatePeer === peer && !privateSeenAcked.has(data.messageId)) {
                        privateSeenAcked.add(data.messageId);
                        const delay = 520 + Math.floor(Math.random() * 350);
                        setTimeout(() => {
                            try {
                                if (socket && currentPrivatePeer === peer) socket.emit('privateMessageSeen', { messageId: data.messageId });
                            } catch {
                                /* ignore */
                            }
                        }, delay);
                    }
                }
            }
        }
        if (!data.outgoing && data.from !== me) {
            alertSound.play().catch(() => {});
        }
    });

    socket.on('privateMessageReadUpdate', ({ messageId, read }) => {
        const id = messageId || null;
        if (!id) return;
        for (const [peer, th] of privateThreads.entries()) {
            const idx = Array.isArray(th.messages)
                ? th.messages.findIndex((m) => m && m.messageId === id)
                : -1;
            if (idx >= 0) {
                th.messages[idx].read = read === true;
                if (currentPrivatePeer === peer) renderPrivateThread(peer);
                break;
            }
        }
    });

    socket.on('privateError', (err) => {
        if (err && err.message) alert(err.message);
    });

    socket.on('displayTyping', ({ username, isTyping, room }) => {
        const typingIndicator = document.getElementById('typingIndicator');
        const label = tKey('typing');
        if (typingIndicator && room === currentRoom) {
            typingIndicator.textContent = isTyping ? `${sanitizeInput(username)} ${label}` : '';
        }
    });

    socket.on('updateUserList', (users) => {
        const listContainer = document.getElementById('sidebarUserList');
        if (!listContainer) return;
        listContainer.innerHTML = '';
        const me = getSecureItem('nickname') || 'Guest';
        users.forEach((user) => {
            if (isBlockedUser(user.username)) return;
            rememberPeerFromListUser(user);
            const userDiv = document.createElement('div');
            userDiv.className = 'user-item sidebar-user-row';
            const avWrap = document.createElement('div');
            avWrap.className = 'sidebar-user-avatar-wrap';
            const av = document.createElement('img');
            av.className = 'sidebar-user-avatar-img';
            av.loading = 'lazy';
            if (user.avatar) av.src = user.avatar;
            else av.classList.add('is-hidden');
            const avPh = document.createElement('span');
            avPh.className = 'sidebar-user-avatar-fallback';
            const un = sanitizeInput(user.username);
            avPh.textContent = un.charAt(0) ? un.charAt(0).toUpperCase() : '?';
            avPh.style.setProperty('--av-hue', String(avatarHueFromString(user.username)));
            if (user.avatar) avPh.classList.add('is-hidden');
            const onDot = document.createElement('span');
            onDot.className = 'sidebar-user-online-dot';
            onDot.title = 'online';
            avWrap.appendChild(av);
            avWrap.appendChild(avPh);
            avWrap.appendChild(onDot);
            const body = document.createElement('div');
            body.className = 'sidebar-user-body';
            const name = document.createElement('span');
            name.className = 'sidebar-user-name';
            name.style.color = user.color || '#0084ff';
            name.textContent = un;
            const meta = document.createElement('div');
            meta.className = 'sidebar-user-meta';
            const gender = document.createElement('span');
            const gch = user.gender === 'female' ? 'female' : user.gender === 'other' ? 'other' : 'male';
            gender.className =
                'sidebar-user-gender ' +
                (gch === 'female'
                    ? 'sidebar-user-gender--female'
                    : gch === 'other'
                      ? 'sidebar-user-gender--other'
                      : 'sidebar-user-gender--male');
            gender.textContent = gch === 'female' ? '♀' : gch === 'other' ? '⚥' : '♂';
            meta.appendChild(gender);
            body.appendChild(name);
            body.appendChild(meta);
            userDiv.appendChild(avWrap);
            userDiv.appendChild(body);
            if (user.username !== me) {
                const actions = document.createElement('div');
                actions.className = 'sidebar-user-actions';
                const reportBtn = document.createElement('button');
                reportBtn.type = 'button';
                reportBtn.className = 'user-action-btn user-action-btn--report';
                reportBtn.textContent = '🚩';
                reportBtn.title = tKey('ctxReport') || 'Report';
                reportBtn.addEventListener('click', (evt) => {
                    evt.stopPropagation();
                    openReportModal(user.username);
                });
                const blockBtn = document.createElement('button');
                blockBtn.type = 'button';
                blockBtn.className = 'user-action-btn user-action-btn--block';
                blockBtn.textContent = '⛔';
                blockBtn.title = tKey('ctxBlock') || 'Block';
                blockBtn.addEventListener('click', (evt) => {
                    evt.stopPropagation();
                    openBlockConfirmModal(user.username);
                });
                actions.appendChild(reportBtn);
                actions.appendChild(blockBtn);
                userDiv.appendChild(actions);
                userDiv.addEventListener('click', (evt) => {
                    evt.stopPropagation();
                    openUserContextMenu(evt, user.username);
                });
            }
            listContainer.appendChild(userDiv);
        });
        filterSidebarUsers();
    });

    socket.on('updateUserCount', (count) => {
        const numEl = document.getElementById('onlineCount');
        if (numEl) numEl.textContent = String(count);
    });

    function setRandomTypingIndicator(username, isTyping) {
        const el = document.getElementById('randomTypingIndicator');
        if (!el) return;
        if (!isTyping) {
            el.textContent = '';
            return;
        }
        const label = tKey('typing') || 'is typing...';
        const u = sanitizeInput(String(username || '')).trim();
        el.textContent = u ? `${u} ${label}` : label;
    }

    socket.on('randomMatched', ({ partner }) => {
        randomLastPaidForFilter = false;
        randomLastPaidForCountry = false;
        setRandomTypingIndicator('', false);
        const title = document.getElementById('randomPartnerTitle');
        if (title) title.textContent = sanitizeInput(String(partner || '…'));
        const area = document.getElementById('randomChatMessages');
        if (area) area.innerHTML = '';
        showRandomSubView('chat');
    });

    socket.on('randomSearchStarted', () => {
        setRandomTypingIndicator('', false);
        showRandomSubView('search');
    });

    socket.on('randomSearchStopped', () => {
        setRandomTypingIndicator('', false);
        showRandomSubView('lobby');
    });

    socket.on('randomDisplayTyping', ({ username, isTyping }) => {
        setRandomTypingIndicator(username, !!isTyping);
    });

    socket.on('randomSessionEnded', (payload = {}) => {
        randomLastPaidForFilter = false;
        randomLastPaidForCountry = false;
        setRandomTypingIndicator('', false);
        showRandomSubView('lobby');
        const area = document.getElementById('randomChatMessages');
        if (area) area.innerHTML = '';
        const title = document.getElementById('randomPartnerTitle');
        if (title) title.textContent = '…';
        // إعادة البحث تلقائياً لكلا الطرفين بعد التخطي إذا كانت الواجهة مفتوحة
        const r = String(payload.reason || '');
        const shouldAuto = !randomBackToLobbyWanted && (randomAutoRestartWanted || r === 'skip' || r === 'partner_skipped');
        randomAutoRestartWanted = false;
        randomBackToLobbyWanted = false;
        if (shouldAuto) {
            setTimeout(() => autoRestartRandomSearchIfPossible(), 150);
        }
    });

    socket.on('randomChatMessage', (data) => {
        const me = getSecureItem('nickname') || '';
        const from = data.from || '';
        const isMine = from === me;
        appendRandomChatLine(data.text || '', data.time || '', isMine);
    });

    socket.on('randomError', (err) => {
        if (randomLastPaidForFilter) {
            addRandomDiamonds(RANDOM_FILTER_COST);
            randomLastPaidForFilter = false;
        }
        if (randomLastPaidForCountry) {
            addRandomDiamonds(RANDOM_COUNTRY_COST);
            randomLastPaidForCountry = false;
        }
        showRandomSubView('lobby');
        if (err && err.message) alert(err.message);
    });

    socket.on('joinRoomDenied', (payload) => {
        const msg = payload?.code === 'girls_only'
            ? tKey('joinRoomDeniedGirls')
            : (payload?.message || '');
        if (msg) alert(msg);
        const rec = joinDeniedRecovery;
        joinDeniedRecovery = null;
        const roomSelection = document.getElementById('roomSelection');
        const chatInterface = document.getElementById('chatInterface');
        const currentRoomName = document.getElementById('currentRoomName');
        if (rec && rec.room) {
            currentRoom = rec.room;
            if (roomSelection) roomSelection.style.display = 'none';
            if (chatInterface) {
                chatInterface.style.display = 'flex';
                chatInterface.style.flexDirection = 'column';
            }
            if (currentRoomName) currentRoomName.textContent = rec.title || rec.room;
            document.body.classList.add('in-room');
            syncRandomFabVisibility();
            const allowPrivateChat = (getSecureItem('privacyPrivateChat') || 'on') === 'on';
            const allowPrivateImages = getSecureItem('privacyImages') || 'everyone';
            socket.emit('joinRoom', {
                username: getSecureItem('nickname') || 'Guest',
                room: rec.room,
                gender: getSecureItem('gender') || 'male',
                allowPrivateChat,
                allowPrivateImages,
                avatar: getAvatarUrl(),
                coverPhoto: getCoverUrl()
            });
        } else {
            currentRoom = '';
            if (roomSelection) roomSelection.style.display = 'block';
            if (chatInterface) chatInterface.style.display = 'none';
            document.body.classList.remove('in-room');
            syncRandomFabVisibility();
        }
    });

    socket.on('randomNotice', (n) => {
        if (n && n.message) alert(n.message);
        else alert(tKey('randomVoiceSoon'));
    });
}
