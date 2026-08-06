(function () {
  'use strict';

  /* ============ 常量与存储 ============ */
  var STORE_KEY = 'qianzai_workbench_v1';
  var META_KEY = 'qianzai_workbench_meta';
  var TODAY = null;          // 当前日期字符串 YYYY-MM-DD
  var YESTERDAY = null;

  var WEIGHT_TARGET_DEFAULT = { target: 0, startWeight: 0, targetDate: '' };

  var EMPTY = {
    reading: [], notes: [], exercise: [], meal: [], weight: [], finance: [],
    plan: [], todo: [], life: [], travel: [],
    choreMembers: [ { id: 'a', name: '倩崽', color: '#D4B8A8' }, { id: 'b', name: '胖崽', color: '#7FB1C9' } ],
    choreDone: {},
    lifeLists: [], lifeItems: [], lifeGroups: [], lifeTemplates: [],
    accounts: [], budgets: [], finCats: [],
    weightTarget: JSON.parse(JSON.stringify(WEIGHT_TARGET_DEFAULT)),
    mealTarget: { kcal: 0, protein: 0, carb: 0, fat: 0 },
    readingGoal: 24,
    exerciseGoal: { monthDays: 15, remindTime: '' },
    exerciseCustomTypes: [],
    exerciseBadgesSeen: [],
    finHide: { asset: false, income: false, expense: false, balance: false }
  };

  function loadState() {
    try {
      var raw = localStorage.getItem(STORE_KEY);
      if (!raw) return JSON.parse(JSON.stringify(EMPTY));
      var s = JSON.parse(raw);
      for (var k in EMPTY) if (!s[k]) s[k] = (k === 'weightTarget' ? JSON.parse(JSON.stringify(WEIGHT_TARGET_DEFAULT)) : (k === 'mealTarget' ? { kcal: 0, protein: 0, carb: 0, fat: 0 } : (k === 'choreDone' ? {} : [])));
      if (!s.weightTarget) s.weightTarget = JSON.parse(JSON.stringify(WEIGHT_TARGET_DEFAULT));
      if (!s.mealTarget) s.mealTarget = { kcal: 0, protein: 0, carb: 0, fat: 0 };
      return s;
    } catch (e) { return JSON.parse(JSON.stringify(EMPTY)); }
  }
  function saveState() { localStorage.setItem(STORE_KEY, JSON.stringify(state)); if (typeof CloudSync !== 'undefined') CloudSync.schedulePush(); }
  function loadMeta() {
    try { return JSON.parse(localStorage.getItem(META_KEY)) || {}; }
    catch (e) { return {}; }
  }
  function saveMeta(m) { localStorage.setItem(META_KEY, JSON.stringify(m)); }

  var state = loadState();

  /* ============ 云端同步（Supabase + 端到端加密） ============
     数据存到 Supabase 这张表里（始终在线）；写入前会用「同步密码」做 AES-GCM 加密，
     密钥由密码经 PBKDF2 派生，密码不下发、不存服务器。
     因此：别人即使拿到数据库里的行，看到的也只是密文；必须知道密码才能解密。
     手机 / 电脑用同一个密码 → 同一把密钥 → 共享同一份数据。忘记密码无法找回。
     未填写 Supabase 配置时自动降级为「本地模式」，不影响原有本地使用。 */
  var CloudSync = (function () {
    var SUPABASE_URL = 'https://phclihevffvwfjyztbyy.supabase.co';  // ← 你的 Supabase 项目 URL
    var SUPABASE_ANON = 'sb_publishable_P--ScLwg0oSjtjARUaImtg_ru6_TIKY';  // ← 你的 anon public key
    var TABLE = 'workbench_state';
    var ROW_ID = 'qianzai_workbench_v1';
    var PASS_KEY = 'qianzai_cloud_pass';
    var client = null, ready = false, suppress = false, pushTimer = null, statusEl = null, pw = '';

    function enabled() {
      return typeof window.supabase !== 'undefined'
        && SUPABASE_URL && SUPABASE_URL.indexOf('YOUR_') !== 0
        && SUPABASE_ANON && SUPABASE_ANON.indexOf('YOUR_') !== 0;
    }
    function pass() { try { return localStorage.getItem(PASS_KEY) || ''; } catch (e) { return ''; } }
    function setPass(v) { try { localStorage.setItem(PASS_KEY, v); } catch (e) {} }
    function setStatus(txt, cls) {
      if (!statusEl) statusEl = $('cloudPill');
      if (!statusEl) return;
      statusEl.textContent = txt;
      statusEl.className = 'cloud-pill' + (cls ? ' ' + cls : '');
    }

    function askPass() {
      return new Promise(function (resolve) {
        $('modalTitle').textContent = '开启云端同步';
        $('modalBody').innerHTML =
          '<p class="muted-tip">设置一个<b>同步密码</b>：手机和电脑用<b>同一个</b>密码，即可共享同一份已加密的数据。' +
          '数据会用该密码端到端加密，云端只存密文。<b>请牢记，忘记无法找回。</b></p>' +
          '<label>同步密码<input type="password" id="cpPass" placeholder="建议 12 位以上、大小写+数字" autocomplete="off" /></label>' +
          '<div class="modal-actions"><button class="btn primary" id="cpOk">开始同步</button>' +
          '<button class="btn ghost" id="cpSkip">仅本地使用</button></div>';
        $('cpOk').onclick = function () {
          var v = $('cpPass').value.trim();
          if (!v) { toast('请输入密码', 'err'); return; }
          setPass(v); closeModal(); resolve(v);
        };
        $('cpSkip').onclick = function () { setPass('__skip__'); closeModal(); resolve(''); };
        showModal();
      });
    }

    /* ---- 端到端加密（Web Crypto：PBKDF2 -> AES-GCM 256） ---- */
    function bufToB64(buf) {
      var bytes = new Uint8Array(buf), s = '';
      for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return btoa(s);
    }
    function b64ToBuf(b64) {
      var bin = atob(b64), bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes.buffer;
    }
    function deriveKey(password, saltBuf) {
      var enc = new TextEncoder();
      return crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey'])
        .then(function (base) {
          return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: saltBuf, iterations: 100000, hash: 'SHA-256' },
            base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        });
    }
    function encryptState(obj, password) {
      var salt = crypto.getRandomValues(new Uint8Array(16));
      var iv = crypto.getRandomValues(new Uint8Array(12));
      return deriveKey(password, salt.buffer).then(function (key) {
        var data = new TextEncoder().encode(JSON.stringify(obj));
        return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, data)
          .then(function (ct) { return { salt: bufToB64(salt.buffer), iv: bufToB64(iv.buffer), ct: bufToB64(ct) }; });
      });
    }
    function decryptState(row, password) {
      var o = JSON.parse(row.data);
      var salt = new Uint8Array(b64ToBuf(o.salt));
      var iv = new Uint8Array(b64ToBuf(o.iv));
      var ct = b64ToBuf(o.ct);
      return deriveKey(password, salt.buffer).then(function (key) {
        return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct)
          .then(function (pt) { return JSON.parse(new TextDecoder().decode(pt)); });
      });
    }

    function fillDefaults(s) {
      for (var k in EMPTY) if (!s[k]) s[k] = (k === 'weightTarget' ? JSON.parse(JSON.stringify(WEIGHT_TARGET_DEFAULT)) : (k === 'mealTarget' ? { kcal: 0, protein: 0, carb: 0, fat: 0 } : (k === 'choreDone' ? {} : [])));
      if (!s.weightTarget) s.weightTarget = JSON.parse(JSON.stringify(WEIGHT_TARGET_DEFAULT));
      if (!s.mealTarget) s.mealTarget = { kcal: 0, protein: 0, carb: 0, fat: 0 };
      return s;
    }

    function start() {
      if (!enabled()) { setStatus('本地模式', 'off'); return Promise.resolve(); }
      setStatus('连接中…', 'busy');
      try { client = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON); }
      catch (e) { console.warn('Supabase 初始化失败', e); setStatus('同步失败', 'err'); return Promise.resolve(); }
      var p = pass();
      if (p === '__skip__') { setStatus('本地模式', 'off'); return Promise.resolve(); }
      if (!p) return askPass().then(applyPass);
      return applyPass(p);
    }

    function applyPass(pv) {
      if (!pv) { setStatus('本地模式', 'off'); return Promise.resolve(); }
      pw = pv; ready = true; setStatus('已同步', 'ok');
      return pull(true);
    }

    function pull(first) {
      if (!ready) return Promise.resolve();
      return client.from(TABLE).select('*').eq('id', ROW_ID).maybeSingle().then(function (res) {
        if (res.error) {
          if (first) { setStatus('已同步', 'ok'); return; }
          console.warn('pull 失败', res.error); setStatus('同步失败', 'err'); return;
        }
        var row = res.data;
        if (!row || !row.data) { setStatus('已同步', 'ok'); return; }
        return decryptState(row, pw).then(function (s) {
          var cloudTs = row.updated_at || 0, localTs = state.__syncTs || 0;
          if (first || cloudTs > localTs) {
            suppress = true;
            s = fillDefaults(s);
            s.__syncTs = cloudTs;
            state = s;
            saveState();
            suppress = false;
            renderAll();
            if (!first) toast('已从其他设备同步最新数据', 'ok');
          }
          setStatus('已同步', 'ok');
        }).catch(function () {
          setStatus('密码错误', 'err');
          toast('同步密码错误，无法解密云端数据', 'err');
          pw = '';
          askPass().then(applyPass);
        });
      }).catch(function (e) {
        if (first) { setStatus('已同步', 'ok'); return; }
        console.warn('pull 失败', e); setStatus('同步失败', 'err');
      });
    }

    function schedulePush() {
      if (!enabled() || !ready || suppress) return;
      setStatus('同步中…', 'busy');
      if (pushTimer) clearTimeout(pushTimer);
      pushTimer = setTimeout(function () { push(); }, 800);
    }

    function push() {
      if (!ready) return Promise.resolve();
      state.__syncTs = Date.now();
      return encryptState(state, pw).then(function (enc) {
        return client.from(TABLE).upsert({ id: ROW_ID, data: JSON.stringify(enc), updated_at: state.__syncTs });
      }).then(function (res) {
        if (res.error) { console.warn('push 失败', res.error); setStatus('同步失败', 'err'); return; }
        setStatus('已同步', 'ok');
      }).catch(function (e) { console.warn('push 失败', e); setStatus('同步失败', 'err'); });
    }

    function syncNow() {
      if (!enabled()) { setStatus('本地模式', 'off'); return; }
      if (!ready) { start(); return; }
      pull(false).then(push);
    }

    function enableFromPill() {
      if (ready) { syncNow(); return; }
      if (!enabled()) { toast('请先在 app.js 顶部 CloudSync 里填写 Supabase 的 URL 和 anon key', 'warn'); return; }
      askPass().then(applyPass);
    }

    return { start: start, schedulePush: schedulePush, syncNow: syncNow, enableFromPill: enableFromPill, isReady: function () { return ready; } };
  })();

  /* ============ 工具函数 ============ */
  function pad(n) { return n < 10 ? '0' + n : '' + n; }
  function fmtDate(d) { return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()); }
  function todayStr() { return fmtDate(new Date()); }
  function dateAdd(dStr, days) {
    var p = dStr.split('-'); var d = new Date(+p[0], +p[1] - 1, +p[2]);
    d.setDate(d.getDate() + days); return fmtDate(d);
  }
  function monthAdd(ym, delta) {
    var y = +ym.slice(0, 4), m = +ym.slice(5, 7) - 1 + delta;
    y += Math.floor(m / 12); m = (m % 12 + 12) % 12;
    return y + '-' + pad(m + 1);
  }
  function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function $(id) { return document.getElementById(id); }
  function radioVal(name) {
    var els = document.getElementsByName(name);
    for (var i = 0; i < els.length; i++) if (els[i].checked) return els[i].value;
    return '';
  }
  function setRadio(name, val) {
    var els = document.getElementsByName(name);
    for (var i = 0; i < els.length; i++) els[i].checked = (els[i].value === val);
  }
  function num(v) { var n = parseFloat(v); return isNaN(n) ? 0 : n; }

  function toast(msg, kind) {
    var wrap = $('toastWrap');
    var t = document.createElement('div');
    t.className = 'toast' + (kind ? ' ' + kind : '');
    t.textContent = msg;
    wrap.appendChild(t);
    setTimeout(function () {
      t.style.transition = 'opacity .3s'; t.style.opacity = '0';
      setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 300);
    }, 3000);
  }

  /* ============ 理财：分类体系与工具 ============ */
  // 支出分类（按需求文档 2026-07-31 更新）
  var EXPENSE_CATS = {
    '食品酒水': ['伙食费', '早餐', '中餐', '晚餐', '水果', '零食', '买菜', '柴米油盐', '饮料酒水', '外出美食'],
    '居家生活': ['房租', '物业费', '电费', '水费', '燃气费', '电视费', '维修费', '快递费'],
    '交流通讯': ['手机话费', '网费', '座机费'],
    '休闲娱乐': ['彩票', '棋牌', '麻将', '话剧', 'K歌', '网游', '运动', '电影', '演唱会', '温泉洗浴', '其他娱乐', '聚会'],
    '人情费用': ['红包', '白事', '升学', '满月', '寿辰', '婚嫁', '乔迁', '孝敬长辈', '请客'],
    '宝宝费用': ['妈妈用品', '医疗护理', '宝宝用品', '宝宝教育', '宝宝食品', '宝宝其他'],
    '出差旅游': ['餐饮费', '交通费', '住宿费', '娱乐费', '出行用品', '其他消费'],
    '行车交通': ['地铁', '公交', '保养', '保险', '违章罚款', '停车', '维修', '驾照', '自行车', '加油', '租车', '飞机', '火车', '打车'],
    '购物消费': ['日常用品', '电子数码', '美妆护肤', '洗护用品', '衣裤鞋帽', '超市购物', '书报杂志', '运动器械', '厨房用品', '家居饰品', '珠宝首饰', '宠物支出', '办公用品', '家具家电', '清洁用品', '汽车用品', '家用纺织'],
    '医疗教育': ['治疗费', '住院费', '护理费', '学费'],
    '其他杂项': ['烂账损失', '意外丢失', '其他支出'],
    '装修费用': ['装修材料', '装修工人', '家电家具', '装修装饰', '装修其他'],
    '金融保险': ['车贷手续', '汽车首付', '车贷', '投资亏损', '人身保险', '按揭还款', '银行手续', '利息支出', '房屋首付', '房贷', '房贷手续', '税费', '赔偿罚款', '消费税收']
  };
  // 收入分类（按需求文档 2026-07-31 更新）
  var INCOME_CATS = {
    '职业收入': ['加班收入', '利息收入', '工资收入', '兼职收入', '理财收入', '奖金收入'],
    '人情收礼': ['所收红包', '满月收礼', '白事收礼', '婚嫁收礼', '乔迁收礼', '升学收礼', '寿辰收礼'],
    '其他收入': ['奖金收入', '中奖收入', '经营所得', '意外来钱']
  };
  var FIN_COLORS = ['#D4B8A8', '#B7C4B1', '#A7B8C9', '#E0C8A0', '#C9A9B0', '#9FB8B0', '#D8BFA8', '#B0A9C4', '#C2B89C', '#A9C0C4', '#CDB6C9'];

  // 二级分类图标映射（emoji）
  var CAT_ICONS = {
    '食品酒水': { '伙食费':'🍚','早餐':'🍳','中餐':'🍱','晚餐':'🍜','水果':'🍎','零食':'🍿','买菜':'🥬','柴米油盐':'🧂','饮料酒水':'🍷','外出美食':'👨‍🍳' },
    '居家生活': { '房租':'🏠','物业费':'🏢','电费':'💡','水费':'💧','燃气费':'🔥','电视费':'📺','维修费':'🔧','快递费':'📦' },
    '交流通讯': { '手机话费':'📱','网费':'🌐','座机费':'☎️' },
    '休闲娱乐': { '彩票':'🎰','棋牌':'🃏','麻将':'🀄','话剧':'🎭','K歌':'🎤','网游':'🎮','运动':'⚽','电影':'🎬','演唱会':'🎵','温泉洗浴':'♨️','其他娱乐':'🎪','聚会':'🥳' },
    '人情费用': { '红包':'🧧','白事':'🕯️','升学':'🎓','满月':'👶','寿辰':'🎂','婚嫁':'💒','乔迁':'🏡','孝敬长辈':'👴','请客':'🍽️' },
    '宝宝费用': { '妈妈用品':'🤰','医疗护理':'💊','宝宝用品':'🍼','宝宝教育':'📚','宝宝食品':'🍼','宝宝其他':'🧸' },
    '出差旅游': { '餐饮费':'🍽️','交通费':'🚗','住宿费':'🏨','娱乐费':'🎡','出行用品':'🧳','其他消费':'💸' },
    '行车交通': { '地铁':'🚇','公交':'🚌','保养':'🔧','保险':'🛡️','违章罚款':'⚠️','停车':'🅿️','维修':'🔧','驾照':'🪙','自行车':'🚲','加油':'⛽','租车':'🚗','飞机':'✈️','火车':'🚅','打车':'🚕' },
    '购物消费': { '日常用品':'🛒','电子数码':'💻','美妆护肤':'💄','洗护用品':'🧴','衣裤鞋帽':'👗','超市购物':'🏪','书报杂志':'📖','运动器械':'🏋️','厨房用品':'🍳','家居饰品':'🏠','珠宝首饰':'💎','宠物支出':'🐾','办公用品':'📝','家具家电':'🛋️','清洁用品':'🧹','汽车用品':'🚙','家用纺织':'🛏️' },
    '医疗教育': { '治疗费':'💉','住院费':'🏥','护理费':'🩹','学费':'🎓' },
    '其他杂项': { '烂账损失':'❌','意外丢失':'😵','其他支出':'📋' },
    '装修费用': { '装修材料':'🧱','装修工人':'👷','家电家具':'🛋️','装修装饰':'🎨','装修其他':'📦' },
    '金融保险': { '车贷手续':'📝','汽车首付':'🚗','车贷':'💳','投资亏损':'📉','人身保险':'🛡️','按揭还款':'🏦','银行手续':'🏧','利息支出':'💸','房屋首付':'🏠','房贷':'🏠','房贷手续':'📝','税费':'📋','赔偿罚款':'⚠️','消费税收':'📊' },
    // 收入分类
    '职业收入': { '加班收入':'💰','利息收入':'📈','工资收入':'💵','兼职收入':'🤝','理财收入':'📊','奖金收入':'🏆' },
    '人情收礼': { '所收红包':'🧧','满月收礼':'👶','白事收礼':'🕯️','婚嫁收礼':'💒','乔迁收礼':'🏡','升学收礼':'🎓','寿辰收礼':'🎂' },
    '其他收入': { '奖金收入':'🏆','中奖收入':'🎰','经营所得':'💼','意外来钱':'🎁' }
  };

  // 返回 [{name, children:[...], isPreset}]（预设在前，自定义在后）
  function getCats(kind) {
    var preset = kind === 'expense' ? EXPENSE_CATS : INCOME_CATS;
    var out = [];
    Object.keys(preset).forEach(function (top) {
      out.push({ name: top, children: preset[top].slice(), isPreset: true });
    });
    (state.finCats || []).filter(function (c) { return c.kind === kind; }).forEach(function (c) {
      if (c.parent === '') {
        var exist = out.find(function (o) { return o.name === c.name; });
        if (!exist) out.push({ name: c.name, children: [], isPreset: false });
      } else {
        var p = out.find(function (o) { return o.name === c.parent; });
        if (p && p.children.indexOf(c.name) < 0) p.children.push(c.name);
      }
    });
    return out;
  }
  function monthKey(dStr) { return dStr.slice(0, 7); }
  function yearKey(dStr) { return dStr.slice(0, 4); }

  // 时间范围 -> {start,end} 含当天
  function getRange(type, start, end) {
    if (type === 'today') return { start: TODAY, end: TODAY };
    if (type === 'week') {
      var d = new Date(); var day = d.getDay() || 7;
      var mon = new Date(d); mon.setDate(d.getDate() - day + 1);
      var sun = new Date(mon); sun.setDate(mon.getDate() + 6);
      return { start: fmtDate(mon), end: fmtDate(sun) };
    }
    if (type === 'month') { var ym = TODAY.slice(0, 7); return { start: ym + '-01', end: ym + '-31' }; }
    if (type === 'quarter') {
      var m = +TODAY.slice(5, 7); var q = Math.floor((m - 1) / 3) * 3 + 1;
      var qy = +TODAY.slice(0, 4);
      var qs = new Date(qy, q - 1, 1); var qe = new Date(qy, q + 2, 1); qe.setDate(0);
      return { start: fmtDate(qs), end: fmtDate(qe) };
    }
    if (type === 'year') { var y = TODAY.slice(0, 4); return { start: y + '-01-01', end: y + '-12-31' }; }
    if (type === 'custom') return { start: start || TODAY, end: end || TODAY };
    return { start: TODAY, end: TODAY };
  }

  function inRange(dStr, r) { return dStr >= r.start && dStr <= r.end; }

  // 账户当前余额（按流水实时计算）
  function acctBalance(a) {
    var bal = num(a.init);
    state.finance.forEach(function (t) {
      if (t.txType === '收入' && t.account === a.id) bal += num(t.amount);
      else if (t.txType === '支出' && t.account === a.id) bal -= num(t.amount);
      else if (t.txType === '转账') {
        if (t.fromAccount === a.id) bal -= num(t.amount);
        if (t.toAccount === a.id) bal += num(t.amount);
      }
    });
    return bal;
  }
  function acctName(id) {
    var a = (state.accounts || []).find(function (x) { return x.id === id; });
    if (a) return a.name;
    if (id === 'deleted') return '已删除账户';
    return '未知账户';
  }
  function money(n) { return (n < 0 ? '-' : '') + '¥' + Math.abs(num(n)).toLocaleString('zh-CN', { maximumFractionDigits: 2 }); }

  /* ============ 跨日检测与自动重置 ============ */
  function runDailyReset() {
    // 模块6：今日计划 —— 顺延昨天未完成的项
    var carry = state.plan.filter(function (p) {
      return p.date === YESTERDAY && p.status !== '已完成';
    });
    carry.forEach(function (p) {
      state.plan.push({
        id: uid(), date: TODAY, time: p.time || '',
        content: p.content, priority: p.priority, status: '未开始'
      });
    });

    // 模块7：待办计划 —— 逾期标记 + 自动归档
    state.todo.forEach(function (t) {
      if ((t.status === '待办' || t.status === '进行中') && t.dueDate < TODAY) {
        t.status = '已延期';
      }
      if (t.status === '已完成' && t.completeDate) {
        if (dateAdd(t.completeDate, 7) <= TODAY) t.isArchived = true;
      }
    });

    saveState();
  }

  function initDay() {
    TODAY = todayStr();
    YESTERDAY = dateAdd(TODAY, -1);
    var meta = loadMeta();
    if (meta.lastVisitDate && meta.lastVisitDate !== TODAY) {
      runDailyReset();
      toast('✨ 新的一天已重置计划与待办');
    }
    saveMeta({ lastVisitDate: TODAY });
  }

  /* ============ 顶部时钟 ============ */
  var WEEK = ['星期日', '星期一', '星期二', '星期三', '星期四', '星期五', '星期六'];
  function tickClock() {
    var d = new Date();
    $('clock').textContent = d.getFullYear() + '年' + (d.getMonth() + 1) + '月' + d.getDate() + '日 ' +
      WEEK[d.getDay()] + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }

  /* ============ 导航 ============ */
  var TITLES = {
    overview: '今日总览', reading: '每月阅读', exercise: '锻炼身体', meal: '好好吃饭',
    weight: '体重管理', finance: '理财管理', todo: '待办计划',
    travel: '旅游记录', chores: '家务排班'
  };
  function goPanel(name) {
    var items = document.querySelectorAll('.nav-item');
    for (var i = 0; i < items.length; i++) items[i].classList.toggle('active', items[i].getAttribute('data-nav') === name);
    var panels = document.querySelectorAll('.panel');
    for (var j = 0; j < panels.length; j++) {
      var on = panels[j].getAttribute('data-panel') === name;
      panels[j].classList.toggle('active', on);
      if (on) { // 重启进入动画
        panels[j].style.animation = 'none'; void panels[j].offsetWidth; panels[j].style.animation = '';
      }
    }
    $('pageTitle').textContent = TITLES[name] || '';
    if (name === 'overview') renderOverview();
    if (name === 'finance') renderFinance();
  }

  /* ============ 通用：增/改/删 框架 ============ */
  // editing[mod] 存正在编辑的记录 id；submit 时决定新增或更新
  var editing = {};
  function startEdit(mod, id) {
    editing[mod] = id;
    var map = {
      exercise: 'e', meal: 'm', weight: 'w', finance: 'f',
      plan: 'p', todo: 't', travel: 'tr'
    };
    var p = map[mod];
    $(p + '-submit').textContent = '保存修改';
    $(p + '-cancel').hidden = false;
    $(p + '-FormTitle').textContent = '编辑中…';
  }
  function cancelEdit(mod) {
    editing[mod] = null;
    var map = { reading: 'r', exercise: 'e', meal: 'm', weight: 'w', finance: 'f', plan: 'p', todo: 't', travel: 'tr' };
    var p = map[mod];
    $(p + '-submit').textContent = '添加';
    $(p + '-cancel').hidden = true;
    $(p + '-FormTitle').textContent = $(p + '-FormTitle').getAttribute('data-default') || '添加';
    clearForm(mod);
  }
  function flashOk(btn) {
    btn.classList.add('ok-flash');
    setTimeout(function () { btn.classList.remove('ok-flash'); }, 600);
  }
  function confirmDel(msg) { return window.confirm(msg || '确定要删除这条记录吗？'); }

  /* ============ 模块1：每月阅读（私人阅读手帐） ============ */
  var readingTab = 'shelf';   // shelf | notes
  var rdView = 'wishlist';      // wishlist | reading | done
  var rdNoteView = 'time';    // time | book
  var rbRating = 0;           // 书籍编辑弹窗中的评分

  // 旧数据迁移：旧记录(date/status/rating/excerpt/thought) -> 书籍 + 笔记
  function migrateReading() {
    if (!state.reading.some(function (r) { return r.createdAt === undefined; })) return;
    var smap = { '在读': '正在读', '读完': '读完', '弃读': '想读' };
    var newBooks = [], newNotes = [];
    state.reading.forEach(function (r) {
      if (r.createdAt !== undefined) { newBooks.push(r); return; }
      var nb = {
        id: r.id || uid(), title: r.title || '未命名', author: r.author || '',
        cover: r.cover || '', status: smap[r.status] || '想读',
        totalPages: 0, currentPages: 0, rating: r.rating || 0, tags: [],
        finishDate: (r.status === '读完') ? (r.date || '') : '', createdAt: r.date || TODAY
      };
      newBooks.push(nb);
      if (r.excerpt) newNotes.push({ id: uid(), bookId: nb.id, type: '摘抄', content: r.excerpt, page: 0, createdAt: r.date || TODAY });
      if (r.thought) newNotes.push({ id: uid(), bookId: nb.id, type: '所悟', content: r.thought, page: 0, createdAt: r.date || TODAY });
    });
    state.reading = newBooks;
    state.notes = (state.notes || []).concat(newNotes);
    saveState();
  }

  function softColor(seed) {
    seed = String(seed || '');
    var h = 0; for (var i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
    return 'hsl(' + (h % 360) + ',42%,82%)';
  }
  function bookCoverHTML(book, cls) {
    if (book.cover) return '<img class="' + cls + '" src="' + esc(book.cover) + '" alt=""/>';
    var letter = (book.title || '?').trim().charAt(0) || '?';
    return '<div class="' + cls + '" style="background:' + softColor(book.id || book.title) + '">' + esc(letter) + '</div>';
  }
  function starsHTML(rating, big) {
    var s = ''; for (var i = 1; i <= 5; i++) s += '<span class="' + (i <= (rating || 0) ? 'on' : 'off') + '">★</span>';
    return '<span class="stars-mini' + (big ? ' big' : '') + '">' + s + '</span>';
  }
  function progressHTML(book) {
    if (!book.totalPages) return '';
    var tp = num(book.totalPages), cp = num(book.currentPages);
    var pct = tp > 0 ? Math.min(100, Math.round(cp / tp * 100)) : 0;
    return '<div class="rd-prog"><div class="rd-prog-fill" style="width:' + pct + '%"></div></div>' +
      '<div class="rd-prog-txt">' + cp + ' / ' + tp + ' 页 · ' + pct + '%</div>';
  }
  function statusTag(status) {
    var cls = status === '读完' ? 'green' : (status === '想读' ? 'muted' : '');
    return '<span class="tag ' + cls + '">' + esc(status) + '</span>';
  }
  function finishedThisYear() {
    var y = TODAY.slice(0, 4);
    return state.reading.filter(function (b) { return b.status === '读完' && b.finishDate && b.finishDate.slice(0, 4) === y; });
  }
  function bookTitle(id) { var b = state.reading.find(function (x) { return x.id === id; }); return b ? b.title : '未知'; }

  function renderReadingSummary() {
    var reading = state.reading.filter(function (b) { return b.status === '正在读'; }).length;
    var done = finishedThisYear().length;
    var goal = state.readingGoal || 24;
    var pct = goal > 0 ? Math.min(100, Math.round(done / goal * 100)) : 0;
    $('rdSummary').innerHTML =
      '<div class="rd-stat-row">' +
        '<div class="rd-stat"><span class="rd-stat-ico">📚</span><span class="rd-stat-num">' + reading + '</span><span class="rd-stat-lbl">在读</span></div>' +
        '<div class="rd-stat rd-click" data-act="year" title="查看年度已读书目"><span class="rd-stat-ico">📖</span><span class="rd-stat-num">' + done + '</span><span class="rd-stat-lbl">今年已读</span></div>' +
        '<div class="rd-stat rd-click" data-act="goal" title="修改年度目标"><span class="rd-stat-ico">🎯</span><span class="rd-stat-num">' + goal + '</span><span class="rd-stat-lbl">年度目标</span></div>' +
      '</div>' +
      '<div class="rd-goal-bar"><div class="rd-goal-fill" style="width:' + pct + '%"></div></div>' +
      '<div class="rd-goal-txt">年度目标完成 ' + pct + '%（已读 ' + done + ' / ' + goal + ' 本）</div>';
  }
  function renderReading() {
    renderReadingSummary();
    var shelf = $('rdShelfPane'), notes = $('rdNotesPane'), detail = $('rdDetail');
    detail.hidden = true;
    if (readingTab === 'shelf') { shelf.hidden = false; notes.hidden = true; renderShelf(); }
    else { shelf.hidden = true; notes.hidden = false; renderNotes(); }
    document.querySelectorAll('[data-rdtab]').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-rdtab') === readingTab); });
  }
  function renderShelf() {
    var books = state.reading.slice().sort(function (a, b) { return (b.createdAt || '') < (a.createdAt || '') ? -1 : 1; });
    if (rdView === 'wishlist') books = books.filter(function (b) { return b.status === '想读'; });
    else if (rdView === 'reading') books = books.filter(function (b) { return b.status === '正在读'; });
    else if (rdView === 'done') books = books.filter(function (b) { return b.status === '读完'; });
    var box = $('rdGrid');
    if (!books.length) {
      box.innerHTML = emptyState(rdView === 'done' ? '📭' : (rdView === 'wishlist' ? '💭' : '📖'), rdView === 'done' ? '今年还没读完书，继续加油' : (rdView === 'wishlist' ? '还没有想读的书，去添加吧' : '正在读的书还没添加'));
      return;
    }
    box.innerHTML = books.map(function (b) {
      var actions;
      if (b.status === '想读') actions = '<button class="btn ghost sm rd-act" data-act="start" data-mod="book" data-id="' + b.id + '">开始阅读</button>';
      else if (b.status === '正在读') actions = '<button class="btn ghost sm rd-act" data-act="finish" data-mod="book" data-id="' + b.id + '">标记读完</button>';
      else actions = '<div class="rd-done-stars">' + starsHTML(b.rating) + '</div>';
      return '<div class="rd-book" data-act="detail" data-mod="book" data-id="' + b.id + '">' +
        '<div class="rd-book-cover">' + bookCoverHTML(b, 'rd-cover') + '</div>' +
        '<div class="rd-book-body">' +
          '<div class="rd-book-top"><div class="rd-book-title">' + esc(b.title) + '</div>' +
            '<button class="icon-btn rd-edit" data-act="edit-book" data-mod="book" data-id="' + b.id + '" title="编辑">✏️</button></div>' +
          (b.author ? '<div class="rd-book-author">' + esc(b.author) + '</div>' : '') +
          '<div class="rd-book-meta">' + statusTag(b.status) +
            (b.tags && b.tags.length ? b.tags.map(function (t) { return '<span class="tag muted">' + esc(t) + '</span>'; }).join('') : '') + '</div>' +
          progressHTML(b) +
          '<div class="rd-book-actions">' + actions +
            '<button class="icon-btn rd-del" data-act="del-book" data-mod="book" data-id="' + b.id + '" title="删除">🗑️</button></div>' +
        '</div></div>';
    }).join('');
  }
  function noteCard(n) {
    var book = state.reading.find(function (x) { return x.id === n.bookId; });
    var typeCls = n.type === '摘抄' ? 'orange' : 'green';
    return '<div class="rd-note">' +
      '<div class="rd-note-head"><span class="tag ' + typeCls + '">' + esc(n.type) + '</span>' +
        '<span class="rd-note-book">' + esc(book ? book.title : '（已删除的书）') + '</span>' +
        (n.page ? '<span class="muted-tip">P' + num(n.page) + '</span>' : '') +
        '<span class="rd-note-date">' + esc(n.createdAt || '') + '</span>' +
        '<span class="rd-note-ops"><button class="icon-btn" data-act="edit-note" data-mod="note" data-id="' + n.id + '" title="编辑">✏️</button>' +
        '<button class="icon-btn" data-act="del-note" data-mod="note" data-id="' + n.id + '" title="删除">🗑️</button></span></div>' +
      '<div class="rd-note-content">' + esc(n.content) + '</div></div>';
  }
  function renderNotes() {
    var box = $('rdNotesList');
    var notes = state.notes.slice().sort(function (a, b) { return (b.createdAt || '') < (a.createdAt || '') ? -1 : 1; });
    if (!notes.length) { box.innerHTML = emptyState('📝', '还没有笔记，读完书顺手记一笔吧'); return; }
    var html = '';
    if (notes.length >= 10) {
      var pick = notes[Math.floor(Math.random() * notes.length)];
      html += '<div class="rd-revisit">💡 重温一条你的笔记：<b>' + esc(bookTitle(pick.bookId)) + '</b> · ' + esc(pick.content) + '</div>';
    }
    if (rdNoteView === 'book') {
      var byBook = {};
      notes.forEach(function (n) { (byBook[n.bookId] = byBook[n.bookId] || []).push(n); });
      html += Object.keys(byBook).map(function (bid) {
        var bk = state.reading.find(function (x) { return x.id === bid; });
        var items = byBook[bid].slice().sort(function (a, b) { return (b.createdAt || '') < (a.createdAt || '') ? -1 : 1; });
        return '<div class="rd-note-group"><div class="rd-note-group-h">📘 ' + esc(bk ? bk.title : '（已删除的书）') + '（' + items.length + '）</div>' +
          items.map(function (n) { return noteCard(n); }).join('') + '</div>';
      }).join('');
    } else {
      html += notes.map(function (n) { return noteCard(n); }).join('');
    }
    box.innerHTML = html;
  }
  function openBookDetail(id) {
    var b = state.reading.find(function (x) { return x.id === id; }); if (!b) return;
    var notes = state.notes.filter(function (n) { return n.bookId === id; }).sort(function (a, c) { return (c.createdAt || '') < (a.createdAt || '') ? -1 : 1; });
    var noteHtml = notes.length ? notes.map(function (n) { return noteCard(n); }).join('') : '<div class="muted-tip">这本书还没有笔记</div>';
    $('rdShelfPane').hidden = true; $('rdNotesPane').hidden = true;
    var d = $('rdDetail'); d.hidden = false; d.setAttribute('data-book', id);
    d.innerHTML = '<div class="rd-detail-head"><button class="btn ghost sm" data-act="back-detail">← 返回书架</button>' +
      (b.status !== '读完' ? '<button class="btn primary sm" data-act="edit-book" data-mod="book" data-id="' + b.id + '">编辑书籍</button>' : '') + '</div>' +
      '<div class="rd-detail-main">' + bookCoverHTML(b, 'rd-cover-lg') +
        '<div class="rd-detail-info"><h3>' + esc(b.title) + '</h3>' +
        (b.author ? '<div class="rd-book-author">' + esc(b.author) + '</div>' : '') +
        '<div class="rd-book-meta">' + statusTag(b.status) + (b.rating ? starsHTML(b.rating, true) : '') +
          (b.finishDate ? '<span class="tag muted">读完于 ' + esc(b.finishDate) + '</span>' : '') + '</div>' +
        (b.totalPages ? '<div class="rd-detail-prog">' + progressHTML(b) + '</div>' : '') +
        (b.tags && b.tags.length ? '<div class="rd-book-meta">' + b.tags.map(function (t) { return '<span class="tag muted">' + esc(t) + '</span>'; }).join('') + '</div>' : '') +
        '</div></div>' +
      '<div class="rd-detail-notes-h">📝 这本书的笔记（' + notes.length + '）</div>' +
      '<div class="rd-detail-notes">' + noteHtml + '</div>' +
      '<button class="btn primary" data-act="add-note-for" data-mod="book" data-id="' + b.id + '">＋ 记笔记</button>';
  }
  function closeDetail() { $('rdDetail').hidden = true; renderReading(); }

  function openBookModal(id) {
    editing.book = id || null;
    var b = id ? state.reading.find(function (x) { return x.id === id; }) : null;
    rbRating = b ? (b.rating || 0) : 0;
    $('modalTitle').textContent = b ? '编辑书籍' : '添加书籍';
    $('modalBody').innerHTML =
      '<label>书名 *<input type="text" id="rb-title" placeholder="书名" value="' + (b ? esc(b.title) : '') + '"/></label>' +
      '<label>作者<input type="text" id="rb-author" placeholder="作者" value="' + (b ? esc(b.author || '') : '') + '"/></label>' +
      '<label>阅读状态<select id="rb-status">' +
        ['想读', '正在读', '读完'].map(function (s) { return '<option value="' + s + '"' + (b && b.status === s ? ' selected' : (!b && s === '想读' ? ' selected' : '')) + '>' + s + '</option>'; }).join('') +
      '</select></label>' +
      '<div class="grid-2">' +
        '<label>总页数<input type="number" id="rb-total" min="0" placeholder="选填" value="' + (b && b.totalPages ? b.totalPages : '') + '"/></label>' +
        '<label>当前页数<input type="number" id="rb-current" min="0" placeholder="选填" value="' + (b && b.currentPages ? b.currentPages : '') + '"/></label>' +
      '</div>' +
      '<label>阅读标签<small style="color:var(--muted)">（逗号分隔，选填）</small><input type="text" id="rb-tags" placeholder="文学, 科幻" value="' + (b && b.tags ? b.tags.join(',') : '') + '"/></label>' +
      '<label>封面<input type="file" id="rb-cover" accept="image/*"/></label>' +
      (b && b.cover ? '<div><img src="' + esc(b.cover) + '" style="max-width:90px;max-height:90px;border-radius:8px;display:block;margin-top:6px"/></div>' : '') +
      '<label>评分<small style="color:var(--muted)">（读完后再评）</small>' +
        '<div class="stars" id="rb-stars">' + [1, 2, 3, 4, 5].map(function (v) { return '<span class="star" data-v="' + v + '">' + (v <= rbRating ? '★' : '☆') + '</span>'; }).join('') + '</div></label>' +
      '<div class="modal-actions"><button class="btn primary" id="rbSave">保存</button><button class="btn ghost" id="rbCancel">取消</button></div>';
    $('rb-stars').addEventListener('click', function (e) {
      if (e.target.classList.contains('star')) {
        var v = +e.target.getAttribute('data-v');
        rbRating = (rbRating === v) ? 0 : v;
        var sp = $('rb-stars').children;
        for (var i = 0; i < sp.length; i++) sp[i].textContent = (i < rbRating ? '★' : '☆');
      }
    });
    $('rbSave').onclick = function () { saveBook(b); };
    $('rbCancel').onclick = closeModal;
    showModal();
  }
  function saveBook(old) {
    var title = $('rb-title').value.trim();
    if (!title) { toast('请填写书名', 'err'); return; }
    var status = $('rb-status').value;
    var obj = {
      id: editing.book || uid(),
      title: title, author: $('rb-author').value.trim(),
      cover: old ? (old.cover || '') : '',
      status: status,
      totalPages: num($('rb-total').value),
      currentPages: num($('rb-current').value),
      rating: rbRating,
      tags: $('rb-tags').value.split(/[,，]/).map(function (t) { return t.trim(); }).filter(Boolean),
      finishDate: old ? (old.finishDate || '') : '',
      createdAt: old ? (old.createdAt || TODAY) : TODAY
    };
    if (status === '读完' && !obj.finishDate) obj.finishDate = TODAY;
    var file = $('rb-cover') && $('rb-cover').files[0];
    var finish = function () {
      if (editing.book) { var i = state.reading.findIndex(function (x) { return x.id === editing.book; }); if (i >= 0) state.reading[i] = obj; }
      else state.reading.push(obj);
      saveState(); closeModal(); renderReading(); renderOverview();
      toast('已保存', 'ok');
    };
    if (file) {
      var reader = new FileReader();
      reader.onload = function () { compressPhoto(reader.result, function (b64) { obj.cover = b64; finish(); }); };
      reader.onerror = finish;
      reader.readAsDataURL(file);
    } else finish();
  }
  function markStatus(id, status) {
    var b = state.reading.find(function (x) { return x.id === id; }); if (!b) return;
    b.status = status;
    if (status === '读完' && !b.finishDate) b.finishDate = TODAY;
    saveState(); renderReading(); renderOverview();
    if (status === '读完') { toast('🎉 读完啦！给个评分吧', 'ok'); openRateModal(id); }
    else if (status === '正在读') { toast('开始阅读：' + b.title, 'ok'); }
  }
  function openRateModal(id) {
    var b = state.reading.find(function (x) { return x.id === id; }); if (!b) return;
    var rt = b.rating || 0;
    $('modalTitle').textContent = '为《' + b.title + '》评分';
    $('modalBody').innerHTML =
      '<div style="text-align:center;font-size:13px;color:var(--muted);margin-bottom:8px">读完于 ' + (b.finishDate || TODAY) + '，打个分吧（可跳过）</div>' +
      '<div class="stars" id="rr-stars" style="justify-content:center;font-size:28px">' +
        [1, 2, 3, 4, 5].map(function (v) { return '<span class="star" data-v="' + v + '">' + (v <= rt ? '★' : '☆') + '</span>'; }).join('') + '</div>' +
      '<div class="modal-actions"><button class="btn primary" id="rrSave">保存评分</button><button class="btn ghost" id="rrSkip">跳过</button></div>';
    $('rr-stars').addEventListener('click', function (e) {
      if (e.target.classList.contains('star')) {
        var v = +e.target.getAttribute('data-v'); rt = (rt === v) ? 0 : v;
        var sp = $('rr-stars').children; for (var i = 0; i < sp.length; i++) sp[i].textContent = (i < rt ? '★' : '☆');
      }
    });
    $('rrSave').onclick = function () { b.rating = rt; saveState(); closeModal(); renderReading(); toast('评分已记录', 'ok'); };
    $('rrSkip').onclick = closeModal;
    showModal();
  }
  function deleteBook(id) {
    var b = state.reading.find(function (x) { return x.id === id; }); if (!b) return;
    if (!window.confirm('确定删除《' + b.title + '》吗？\n该书关联的所有笔记也会一并删除，此操作不可恢复。')) return;
    state.reading = state.reading.filter(function (x) { return x.id !== id; });
    state.notes = state.notes.filter(function (n) { return n.bookId !== id; });
    saveState(); $('rdDetail').hidden = true; renderReading(); renderOverview();
    toast('已删除', 'ok');
  }
  function openNoteModal(bookId, noteId) {
    editing.note = noteId || null;
    var n = noteId ? state.notes.find(function (x) { return x.id === noteId; }) : null;
    var preBook = bookId || (n ? n.bookId : '');
    var opts = state.reading.map(function (b) { return '<option value="' + b.id + '"' + (b.id === preBook ? ' selected' : '') + '>' + esc(b.title) + '</option>'; }).join('');
    if (!opts) opts = '<option value="">（请先在书架添加一本书）</option>';
    $('modalTitle').textContent = n ? '编辑笔记' : '记笔记';
    $('modalBody').innerHTML =
      '<label>关联书籍 *<select id="nt-book">' + opts + '</select></label>' +
      '<label>笔记类型<select id="nt-type">' +
        ['摘抄', '所悟'].map(function (t) { return '<option value="' + t + '"' + (n && n.type === t ? ' selected' : (!n && t === '摘抄' ? ' selected' : '')) + '>' + t + '</option>'; }).join('') +
      '</select></label>' +
      '<label>内容 *<textarea id="nt-content" rows="4" placeholder="写点什么">' + (n ? esc(n.content) : '') + '</textarea></label>' +
      '<label>关联页码<input type="number" id="nt-page" min="0" placeholder="选填" value="' + (n && n.page ? n.page : '') + '"/></label>' +
      '<div class="modal-actions"><button class="btn primary" id="ntSave">保存</button><button class="btn ghost" id="ntCancel">取消</button></div>';
    $('ntSave').onclick = function () { saveNote(n); };
    $('ntCancel').onclick = closeModal;
    showModal();
  }
  function saveNote(old) {
    var bookId = $('nt-book').value;
    if (!bookId) { toast('请先选择关联书籍（在书架添加一本书）', 'err'); return; }
    var content = $('nt-content').value.trim();
    if (!content) { toast('请填写笔记内容', 'err'); return; }
    if (!state.reading.some(function (b) { return b.id === bookId; })) { toast('关联的书籍不存在', 'err'); return; }
    var obj = {
      id: editing.note || uid(), bookId: bookId, type: $('nt-type').value, content: content,
      page: num($('nt-page').value), createdAt: old ? (old.createdAt || TODAY) : TODAY
    };
    if (editing.note) { var i = state.notes.findIndex(function (x) { return x.id === editing.note; }); if (i >= 0) state.notes[i] = obj; }
    else state.notes.push(obj);
    saveState(); closeModal(); renderReading(); renderOverview();
    toast('笔记已保存', 'ok');
  }
  function deleteNote(id) {
    if (!confirmDel('确定删除这条笔记吗？')) return;
    state.notes = state.notes.filter(function (x) { return x.id !== id; });
    saveState();
    var d = $('rdDetail');
    if (!d.hidden && d.getAttribute('data-book')) openBookDetail(d.getAttribute('data-book'));
    else renderReading();
    renderOverview();
  }
  function openYearModal() {
    var y = TODAY.slice(0, 4);
    var done = finishedThisYear();
    var goal = state.readingGoal || 24;
    var fav = done.slice().sort(function (a, b) { return (b.rating || 0) - (a.rating || 0); })[0];
    var noteCount = state.notes.filter(function (n) { return done.some(function (d) { return d.id === n.bookId; }); }).length;
    var byMonth = {};
    done.forEach(function (b) { var m = +b.finishDate.slice(5, 7); (byMonth[m] = byMonth[m] || []).push(b); });
    var months = Object.keys(byMonth).map(Number).sort(function (a, b) { return a - b; });
    var wall = months.map(function (m) {
      return '<div class="rd-year-month">✨ ' + m + '月（' + byMonth[m].length + ' 本）</div>' +
        '<div class="rd-year-wall">' + byMonth[m].map(function (b) {
          return '<div class="rd-year-thumb" title="' + esc(b.title) + '">' + bookCoverHTML(b, 'rd-year-cover') +
            '<span class="rd-year-cap">' + esc((b.title || '').slice(0, 6)) + '</span></div>';
        }).join('') + '</div>';
    }).join('');
    $('modalTitle').textContent = y + ' 年度阅读总结';
    $('modalBody').innerHTML =
      '<div class="rd-year-summary">' +
        '<div class="rd-year-cell"><div class="k">共读</div><div class="v">' + done.length + ' 本</div></div>' +
        '<div class="rd-year-cell"><div class="k">最爱</div><div class="v">' + (fav ? '★' + fav.rating + ' 《' + esc(fav.title.slice(0, 8)) + '》' : '—') + '</div></div>' +
        '<div class="rd-year-cell"><div class="k">笔记</div><div class="v">' + noteCount + ' 条</div></div>' +
        '<div class="rd-year-cell"><div class="k">目标</div><div class="v">' + done.length + ' / ' + goal + '</div></div>' +
      '</div>' +
      (done.length ? wall : '<div class="empty"><span class="em">📚</span>今年还没读完一本书，去书架标记读完吧</div>') +
      '<div class="modal-actions"><button class="btn ghost" id="ryClose">关闭</button></div>';
    $('ryClose').onclick = closeModal;
    showModal();
  }
  function openGoalModal() {
    $('modalTitle').textContent = '年度阅读目标';
    $('modalBody').innerHTML =
      '<label>年度目标（本）<input type="number" id="rg-goal" min="1" value="' + (state.readingGoal || 24) + '"/></label>' +
      '<div class="modal-actions"><button class="btn primary" id="rgSave">保存</button><button class="btn ghost" id="rgCancel">取消</button></div>';
    $('rgSave').onclick = function () {
      var g = num($('rg-goal').value);
      if (g <= 0) { toast('目标需大于0', 'err'); return; }
      state.readingGoal = g; saveState(); closeModal(); renderReading(); renderOverview();
      toast('目标已更新', 'ok');
    };
    $('rgCancel').onclick = closeModal;
    showModal();
  }

  /* ============ 模块2：锻炼 ============ */
  /* ============ 模块2：锻炼身体（运动记录助手） ============ */
  var EX_CATS = {
    '跑步': ['户外跑', '跑步机', '越野跑'],
    '球类': ['篮球', '足球', '羽毛球', '乒乓球', '网球'],
    '健身': ['力量训练', '有氧操', 'HIIT', '瑜伽', '普拉提'],
    '骑行': ['户外骑行', '动感单车'],
    '游泳': ['自由泳', '蛙泳', '其他'],
    '户外': ['登山', '徒步', '滑雪'],
    '其他': ['跳绳', '划船机', '椭圆机', '其他']
  };
  var EX_DEFAULT_DUR = {
    '户外跑': 30, '跑步机': 30, '越野跑': 45, '篮球': 60, '足球': 60, '羽毛球': 45, '乒乓球': 40,
    '网球': 60, '力量训练': 40, '有氧操': 30, 'HIIT': 20, '瑜伽': 45, '普拉提': 40, '户外骑行': 45,
    '动感单车': 40, '自由泳': 40, '蛙泳': 40, '其他': 30, '登山': 120, '徒步': 90, '滑雪': 120,
    '跳绳': 15, '划船机': 30, '椭圆机': 30
  };
  var EX_CAL_PER_MIN = { '跑步': 10, '球类': 9, '健身': 8, '骑行': 8, '游泳': 11, '户外': 7, '其他': 6 };
  var EX_CHART_COLORS = ['#D4B8A8', '#9CAF88', '#8AA0B5', '#E8B98A', '#C9A0C9', '#B5C9A0', '#E0A0A0'];
  var EX_BADGES = [
    { key: 'first', icon: '🏅', name: '首次运动', desc: '完成第一条运动记录' },
    { key: 'streak7', icon: '📅', name: '连续7天', desc: '连续打卡7天' },
    { key: 'streak30', icon: '📅', name: '连续30天', desc: '连续打卡30天' },
    { key: 'streak100', icon: '📅', name: '连续100天', desc: '连续打卡100天' },
    { key: 'total30', icon: '🏃', name: '运动达人', desc: '累计运动30天' },
    { key: 'total100', icon: '🏃', name: '运动狂人', desc: '累计运动100天' },
    { key: 'monthGoal', icon: '💪', name: '月度达标', desc: '完成月度目标' },
    { key: 'allround', icon: '🌟', name: '全能选手', desc: '完成过5种以上运动类型' }
  ];

  var exRange = 'week';        // week | month | year | all

  function nowTime() { var d = new Date(); return pad(d.getHours()) + ':' + pad(d.getMinutes()); }
  function exCatOf(type) {
    for (var c in EX_CATS) if (EX_CATS[c].indexOf(type) >= 0) return c;
    if (state.exerciseCustomTypes && state.exerciseCustomTypes.indexOf(type) >= 0) return '其他';
    return '其他';
  }
  function exDefaultDur(type) { return EX_DEFAULT_DUR[type] || 30; }
  function exEstimateCal(type, dur, intensity) {
    var rate = EX_CAL_PER_MIN[exCatOf(type)] || 6;
    var mul = intensity === '高' ? 1.2 : (intensity === '低' ? 0.85 : 1);
    return Math.round(dur * rate * mul);
  }
  function exDaysSet(records) { var s = {}; records.forEach(function (r) { s[r.date] = 1; }); return s; }
  function exMonthRecords() { var ym = TODAY.slice(0, 7); return state.exercise.filter(function (r) { return r.date.slice(0, 7) === ym; }); }
  function exStreak() {
    var d = TODAY, n = 0;
    var hasToday = state.exercise.some(function (r) { return r.date === TODAY; });
    if (!hasToday) d = dateAdd(TODAY, -1);
    while (state.exercise.some(function (r) { return r.date === d; })) { n++; d = dateAdd(d, -1); }
    return n;
  }
  function exBestStreak() {
    var days = Object.keys(exDaysSet(state.exercise)).sort();
    var best = 0, cur = 0, prev = null;
    days.forEach(function (d) { if (prev && dateAdd(prev, 1) === d) cur++; else cur = 1; if (cur > best) best = cur; prev = d; });
    return best;
  }
  function exCumulativeDays() { return Object.keys(exDaysSet(state.exercise)).length; }
  function exDistinctTypes() { var s = {}; state.exercise.forEach(function (r) { s[r.type] = 1; }); return Object.keys(s).length; }
  function exRecentTypes() {
    var seen = {}, out = [];
    var recs = state.exercise.slice().sort(function (a, b) { return (a.date + a.time) < (b.date + b.time) ? 1 : -1; });
    recs.forEach(function (r) { if (!seen[r.type]) { seen[r.type] = 1; out.push(r.type); } });
    return out.slice(0, 3);
  }
  function exTypeOptions(selected) {
    var recent = exRecentTypes(), html = '';
    if (recent.length) {
      html += '<optgroup label="最近使用">';
      recent.forEach(function (t) { html += '<option value="' + esc(t) + '"' + (t === selected ? ' selected' : '') + '>' + esc(t) + '</option>'; });
      html += '</optgroup>';
    }
    for (var c in EX_CATS) {
      html += '<optgroup label="' + esc(c) + '">';
      EX_CATS[c].forEach(function (t) { html += '<option value="' + esc(t) + '"' + (t === selected ? ' selected' : '') + '>' + esc(t) + '</option>'; });
      html += '</optgroup>';
    }
    if (state.exerciseCustomTypes && state.exerciseCustomTypes.length) {
      html += '<optgroup label="自定义">';
      state.exerciseCustomTypes.forEach(function (t) { html += '<option value="' + esc(t) + '"' + (t === selected ? ' selected' : '') + '>' + esc(t) + '</option>'; });
      html += '</optgroup>';
    }
    return html;
  }
  function exRangeLabel() { return { week: '本周', month: '本月', year: '本年', all: '全部' }[exRange]; }

  function renderExercise() {
    renderExerciseSummary();
    renderExerciseToday();
    renderExerciseStats();
  }
  function renderExerciseSummary() {
    var month = exMonthRecords();
    var days = Object.keys(exDaysSet(month)).length;
    var count = month.length;
    var streak = exStreak();
    var goal = (state.exerciseGoal && state.exerciseGoal.monthDays) || 15;
    var pct = goal > 0 ? Math.min(100, Math.round(days / goal * 100)) : 0;
    var done = goal > 0 && days >= goal;
    $('exSummary').innerHTML =
      '<div class="rd-stat-row">' +
        '<div class="rd-stat"><span class="rd-stat-ico">📅</span><span class="rd-stat-num">' + days + '</span><span class="rd-stat-lbl">本月运动天数</span></div>' +
        '<div class="rd-stat"><span class="rd-stat-ico">🏋️</span><span class="rd-stat-num">' + count + '</span><span class="rd-stat-lbl">本月运动次数</span></div>' +
        '<div class="rd-stat"><span class="rd-stat-ico">🔥</span><span class="rd-stat-num">' + streak + '</span><span class="rd-stat-lbl">连续打卡</span></div>' +
        '<div class="rd-stat rd-click" data-act="ex-goal" title="设定月度目标"><span class="rd-stat-ico">🎯</span><span class="rd-stat-num">' + goal + '</span><span class="rd-stat-lbl">月度目标</span></div>' +
      '</div>' +
      '<div class="rd-goal-bar"><div class="rd-goal-fill' + (pct >= 80 ? ' green' : (pct < 50 ? ' yellow' : '')) + '" style="width:' + pct + '%"></div></div>' +
      '<div class="rd-goal-txt">' + (done ? '🎉 本月目标已达成！' : '月度目标完成 ' + pct + '%（' + days + ' / ' + goal + ' 天）') + '</div>';
  }
  function renderExerciseToday() {
    var tCount = state.exercise.filter(function (r) { return r.date === TODAY; }).length;
    var msg = tCount > 0 ? ('今日已运动 ' + tCount + ' 次，很棒！🔥') : '今天还没有运动哦，动起来吧 💪';
    $('exToday').innerHTML =
      '<div class="ex-today-left"><div class="ex-today-ico">💪</div><div><div class="ex-today-title">今日打卡</div><div class="ex-today-sub">' + msg + '</div></div></div>';
  }
  function renderExerciseCalendar() {
    if (!exCalMonth) exCalMonth = TODAY.slice(0, 7);
    var y = +exCalMonth.slice(0, 4), m = +exCalMonth.slice(5, 7);
    $('exCalLabel').textContent = y + '年' + m + '月';
    var startDow = new Date(y, m - 1, 1).getDay();
    var daysInMonth = new Date(y, m, 0).getDate();
    var byDay = {};
    state.exercise.forEach(function (r) { if (r.date.slice(0, 7) === exCalMonth) byDay[r.date] = (byDay[r.date] || 0) + 1; });
    var html = '<div class="ex-cal-grid ex-cal-dows">';
    ['日', '一', '二', '三', '四', '五', '六'].forEach(function (w) { html += '<div class="ex-cal-dow">' + w + '</div>'; });
    html += '</div><div class="ex-cal-grid">';
    for (var i = 0; i < startDow; i++) html += '<div class="ex-cal-cell empty"></div>';
    for (var d = 1; d <= daysInMonth; d++) {
      var ds = exCalMonth + '-' + (d < 10 ? '0' + d : d);
      var cnt = byDay[ds] || 0;
      var cls = 'ex-cal-cell';
      if (ds === TODAY) cls += ' today';
      if (exSelDate === ds) cls += ' selected';
      var dot = cnt ? '<span class="ex-dot' + (cnt > 1 ? ' multi' : '') + '">' + (cnt > 1 ? cnt : '') + '</span>' : '';
      html += '<div class="' + cls + '" data-act="ex-day" data-day="' + ds + '"><span class="ex-cal-num">' + d + '</span>' + dot + '</div>';
    }
    html += '</div>';
    $('exCal').innerHTML = html;
    renderExDayList();
  }
  function renderExDayList() {
    var list = state.exercise.slice().sort(function (a, b) { return (a.date + a.time) < (b.date + b.time) ? 1 : -1; });
    var box = $('exDayList');
    if (exSelDate) list = list.filter(function (r) { return r.date === exSelDate; });
    if (!list.length) { box.innerHTML = emptyState('📭', exSelDate ? '这一天还没有运动记录' : '还没有运动记录，开始动起来吧 💪'); return; }
    var head = exSelDate ? ('<div class="ex-day-head">' + exSelDate + ' 的运动（' + list.length + '）<button class="btn ghost sm" data-act="ex-all">查看全部记录</button></div>') : '';
    box.innerHTML = head + list.map(function (r) {
      var extra = [];
      if (r.intensity) extra.push('强度 ' + r.intensity);
      if (r.calories) extra.push('约 ' + r.calories + ' kcal');
      if (r.feeling) extra.push(esc(r.feeling));
      return itemHTML(r.id, 'exercise',
        '<span>' + esc(r.type) + '</span><span class="tag">' + r.duration + ' 分钟</span>',
        esc(r.date) + (r.time ? ' ' + esc(r.time) : '') + (extra.length ? ' · ' + extra.join(' · ') : ''));
    }).join('');
  }
  function exRangeRecords() {
    var recs = state.exercise, now = new Date();
    if (exRange === 'week') return recs.filter(function (r) { return r.date >= dateAdd(TODAY, -6) && r.date <= TODAY; });
    if (exRange === 'month') { var ym = TODAY.slice(0, 7); return recs.filter(function (r) { return r.date.slice(0, 7) === ym; }); }
    if (exRange === 'year') { var y = TODAY.slice(0, 4); return recs.filter(function (r) { return r.date.slice(0, 4) === y; }); }
    return recs;
  }
  function exBuckets(recs) {
    var buckets = [];
    if (exRange === 'week') {
      for (var i = 6; i >= 0; i--) { var ds = dateAdd(TODAY, -i); buckets.push({ key: ds, label: ds.slice(5), value: 0 }); }
      recs.forEach(function (r) { var b = buckets.filter(function (x) { return x.key === r.date; })[0]; if (b) b.value++; });
    } else if (exRange === 'month') {
      var ym = TODAY.slice(0, 7), dim = new Date(+ym.slice(0, 4), +ym.slice(5, 7), 0).getDate();
      for (var d = 1; d <= dim; d++) { var ds2 = ym + '-' + (d < 10 ? '0' + d : d); buckets.push({ key: ds2, label: '' + d, value: 0 }); }
      recs.forEach(function (r) { var b = buckets.filter(function (x) { return x.key === r.date; })[0]; if (b) b.value++; });
    } else {
      var map = {}; recs.forEach(function (r) { var k = r.date.slice(0, 7); map[k] = (map[k] || 0) + 1; });
      Object.keys(map).sort().forEach(function (k) { buckets.push({ key: k, label: k.slice(5) + '月', value: map[k] }); });
    }
    return buckets;
  }
  function exBarChart(buckets) {
    var max = 1; buckets.forEach(function (b) { if (b.value > max) max = b.value; });
    var n = buckets.length, W = 320, H = 160, padB = 24, padT = 12, padX = 6;
    var bw = (W - padX * 2) / n, chartH = H - padB - padT, bars = '';
    buckets.forEach(function (b, i) {
      var h = Math.round(b.value / max * chartH), x = padX + i * bw + bw * 0.18, w = bw * 0.64, y = padT + (chartH - h);
      bars += '<rect x="' + x + '" y="' + y + '" width="' + w + '" height="' + h + '" rx="3" fill="#D4B8A8"/>';
      if (b.value) bars += '<text x="' + (x + w / 2) + '" y="' + (y - 3) + '" font-size="9" text-anchor="middle" fill="#7a6a60">' + b.value + '</text>';
      bars += '<text x="' + (x + w / 2) + '" y="' + (H - 8) + '" font-size="8" text-anchor="middle" fill="#a99b90">' + esc(b.label) + '</text>';
    });
    return '<svg viewBox="0 0 ' + W + ' ' + H + '" class="ex-chart" preserveAspectRatio="xMidYMid meet">' + bars + '</svg>';
  }
  function exDonut(segs) {
    var total = 0; segs.forEach(function (s) { total += s.value; });
    var W = 160, H = 160, cx = 80, cy = 80, r = 54, sw = 20, circ = 2 * Math.PI * r, acc = 0, arcs = '';
    segs.forEach(function (s) {
      var len = (s.value / total) * circ, off = -acc * circ;
      arcs += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' + s.color + '" stroke-width="' + sw + '" stroke-dasharray="' + len + ' ' + (circ - len) + '" stroke-dashoffset="' + off + '" transform="rotate(-90 ' + cx + ' ' + cy + ')"/>';
      acc += s.value / total;
    });
    return '<svg viewBox="0 0 ' + W + ' ' + H + '" class="ex-donut" preserveAspectRatio="xMidYMid meet"><circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="#F0EDEA" stroke-width="' + sw + '"/><circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="#F0EDEA" stroke-width="' + sw + '"/>' + arcs + '<text x="' + cx + '" y="' + (cy - 2) + '" font-size="18" text-anchor="middle" fill="#5b4f47" font-weight="600">' + total + '</text><text x="' + cx + '" y="' + (cy + 16) + '" font-size="10" text-anchor="middle" fill="#a99b90">总次数</text></svg>';
  }
  function renderExerciseStats() {
    var box = $('exStats');
    if (!state.exercise.length) { box.innerHTML = emptyState('📭', '还没有运动记录，开始动起来吧 💪'); return; }
    var recs = exRangeRecords();
    var buckets = exBuckets(recs);
    var catCount = {};
    recs.forEach(function (r) { var c = exCatOf(r.type); catCount[c] = (catCount[c] || 0) + 1; });
    var segs = Object.keys(catCount).map(function (c, i) { return { label: c, value: catCount[c], color: EX_CHART_COLORS[i % EX_CHART_COLORS.length] }; });
    var few = state.exercise.length < 3;
    // 统计数据跟随选中范围
    var rDays = Object.keys(exDaysSet(recs)).length;
    var rCount = recs.length;
    var rMins = recs.reduce(function (s, r) { return s + num(r.duration); }, 0);
    // 最佳纪录：连续打卡基于当前范围记录
    var rangeDates = Object.keys(exDaysSet(recs)).sort();
    var bestStreak = 0, curStreak = 0, prevDate = null;
    rangeDates.forEach(function (d) { if (prevDate && dateAdd(prevDate, 1) === d) curStreak++; else curStreak = 1; if (curStreak > bestStreak) bestStreak = curStreak; prevDate = d; });
    // 单周期最高次数
    var periodMax = 0;
    if (exRange === 'week') periodMax = rCount;
    else if (exRange === 'month' || exRange === 'year') {
      var pCounts = {}; recs.forEach(function (r) { var k = r.date.slice(0, 7); pCounts[k] = (pCounts[k] || 0) + 1; });
      Object.keys(pCounts).forEach(function (k) { if (pCounts[k] > periodMax) periodMax = pCounts[k]; });
    } else periodMax = rCount;

    var rangeLabel = exRangeLabel();
    box.innerHTML =
      '<div class="ex-sec-title">🥧 运动类型分布</div>' +
      (few ? '<div class="muted-tip">📊 再多记录几次，统计图表就会出现了</div>' : '<div class="ex-donut-wrap">' + exDonut(segs) + '<div class="ex-donut-legend">' + segs.map(function (s) { return '<span class="ex-leg"><i style="background:' + s.color + '"></i>' + esc(s.label) + ' ' + s.value + '</span>'; }).join('') + '</div></div>') +
      '<div class="ex-sec-title">📊 ' + rangeLabel + '统计</div>' +
      '<div class="ov-grid">' +
        '<div class="ov-cell"><div class="k">' + rangeLabel + '运动天数</div><div class="v">' + rDays + ' 天</div></div>' +
        '<div class="ov-cell"><div class="k">' + rangeLabel + '运动次数</div><div class="v">' + rCount + ' 次</div></div>' +
        '<div class="ov-cell"><div class="k">' + rangeLabel + '总时长</div><div class="v">' + rMins + ' 分钟</div></div>' +
      '</div>' +
      '<div class="ex-sec-title">🏆 最佳纪录（' + rangeLabel + '）</div>' +
      '<div class="ov-grid">' +
        '<div class="ov-cell"><div class="k">最长连续打卡</div><div class="v">' + bestStreak + ' 天</div></div>' +
        '<div class="ov-cell"><div class="k">单' + (exRange === 'week' ? '周' : (exRange === 'month' ? '月' : (exRange === 'year' ? '年' : ''))) + '最高次数</div><div class="v">' + periodMax + ' 次</div></div>' +
      '</div>' +
      renderBadgesHTML();
  }
  function exComputeBadges() {
    var month = exMonthRecords(), days = Object.keys(exDaysSet(month)).length;
    var goal = (state.exerciseGoal && state.exerciseGoal.monthDays) || 15;
    return {
      first: state.exercise.length >= 1,
      streak7: exBestStreak() >= 7, streak30: exBestStreak() >= 30, streak100: exBestStreak() >= 100,
      total30: exCumulativeDays() >= 30, total100: exCumulativeDays() >= 100,
      monthGoal: goal > 0 && days >= goal, allround: exDistinctTypes() >= 5
    };
  }
  function renderBadgesHTML() {
    var earned = exComputeBadges();
    var html = '<div class="ex-sec-title">🏅 我的徽章</div><div class="ex-badges">';
    EX_BADGES.forEach(function (b) {
      var on = earned[b.key];
      html += '<div class="ex-badge' + (on ? ' on' : '') + '" title="' + esc(b.desc) + '"><div class="ex-badge-ico">' + (on ? b.icon : '🔒') + '</div><div class="ex-badge-name">' + esc(b.name) + '</div></div>';
    });
    return html + '</div>';
  }
  function syncBadges(announce) {
    var earned = exComputeBadges(), seen = state.exerciseBadgesSeen || [], changed = false;
    EX_BADGES.forEach(function (b) {
      if (earned[b.key] && seen.indexOf(b.key) < 0) { if (announce) toast('🎉 获得新徽章：' + b.name, 'ok'); seen.push(b.key); changed = true; }
    });
    state.exerciseBadgesSeen = seen;
    if (changed) saveState();
  }
  function confettiBurst() {
    var emojis = ['🎉', '⭐', '💪', '✨', '🏅'];
    for (var i = 0; i < 24; i++) {
      (function () {
        var s = document.createElement('div');
        s.textContent = emojis[i % emojis.length];
        s.style.cssText = 'position:fixed;left:' + (Math.random() * 100) + 'vw;top:-30px;font-size:' + (16 + Math.random() * 18) + 'px;z-index:9999;pointer-events:none;opacity:1;transition:transform 1.6s ease-in,opacity 1.6s;';
        document.body.appendChild(s);
        setTimeout(function () { s.style.transform = 'translateY(110vh) rotate(' + (Math.random() * 360) + 'deg)'; s.style.opacity = '0'; }, 20);
        setTimeout(function () { if (s.parentNode) s.parentNode.removeChild(s); }, 1900);
      })();
    }
  }
  function pickEncourage() {
    var arr = ['打卡成功，今天也是自律的一天 💪', '动起来啦，身体会感谢你 🔥', '坚持就是胜利，继续加油！', '又离目标近了一步 🎯', '运动完心情都变好了吧 ✨'];
    return arr[Math.floor(Math.random() * arr.length)];
  }
  function checkGoalCelebration() {
    var month = exMonthRecords(), days = Object.keys(exDaysSet(month)).length;
    var goal = (state.exerciseGoal && state.exerciseGoal.monthDays) || 15;
    var met = goal > 0 && days >= goal;
    if (met && !state.exerciseGoalDone) { state.exerciseGoalDone = true; saveState(); confettiBurst(); toast('🎉 本月运动目标达成！', 'ok'); }
    else if (!met) state.exerciseGoalDone = false;
  }
  function openExerciseModal(id, mode) {
    editing.exercise = id || null;
    var rec = id ? state.exercise.find(function (x) { return x.id === id; }) : null;
    var initMode = mode || (rec ? 'detail' : 'quick');
    var defType = rec ? rec.type : (exRecentTypes()[0] || '户外跑');
    var defDur = rec ? rec.duration : exDefaultDur(defType);
    var defCal = rec ? (rec.calories || '') : '';
    var defInt = rec ? (rec.intensity || '中等') : '中等';
    $('modalTitle').textContent = rec ? '编辑记录' : '记录运动';
    $('modalBody').innerHTML =
      '<div class="seg" id="exModeSeg" style="margin-bottom:12px"><button class="' + (initMode === 'quick' ? 'active' : '') + '" data-exmode="quick">⚡ 快速打卡</button><button class="' + (initMode === 'detail' ? 'active' : '') + '" data-exmode="detail">📝 详细记录</button></div>' +
      '<label>运动类型 *<select id="ex-type">' + exTypeOptions(defType) + '</select></label>' +
      '<div class="ex-custom-row"><label>或自定义新类型<input type="text" id="ex-newtype" placeholder="如：攀岩" style="margin-top:4px"/><button class="btn ghost sm" id="ex-addtype" style="margin-top:6px">＋ 添加类型</button></label></div>' +
      '<label>运动时长(分钟) *<input type="number" id="ex-dur" min="1" value="' + defDur + '"/></label>' +
      '<div id="ex-detail-fields" style="display:' + (initMode === 'detail' ? 'block' : 'none') + '">' +
        '<label>运动日期<input type="date" id="ex-date" value="' + (rec ? rec.date : TODAY) + '"/></label>' +
        '<label>消耗卡路里(千卡)<input type="number" id="ex-cal" min="0" placeholder="自动估算" value="' + defCal + '"/></label>' +
        '<label>运动强度<select id="ex-intensity"><option value="低">低</option><option value="中等"' + (defInt === '中等' ? ' selected' : '') + '>中等</option><option value="高">高</option></select></label>' +
        '<label>运动感受<input type="text" id="ex-feeling" placeholder="今天状态不错💪" value="' + (rec ? esc(rec.feeling || '') : '') + '"/></label>' +
        '<label>备注<textarea id="ex-note" rows="2" placeholder="晨跑，空气很好">' + (rec ? esc(rec.note || '') : '') + '</textarea></label>' +
      '</div>' +
      '<div class="modal-actions"><button class="btn primary" id="exSave">' + (initMode === 'detail' || rec ? '保存记录' : '打卡') + '</button><button class="btn ghost" id="exCancel">取消</button></div>';
    $('exModeSeg').addEventListener('click', function (e) {
      var b = e.target.closest('[data-exmode]'); if (!b) return;
      setSegActive($('exModeSeg'), b);
      var m = b.getAttribute('data-exmode');
      $('ex-detail-fields').style.display = (m === 'detail') ? 'block' : 'none';
      $('exSave').textContent = (m === 'detail') ? '保存记录' : '打卡';
      if (m === 'detail' && !rec) { $('ex-date').value = TODAY; $('ex-cal').value = exEstimateCal($('ex-type').value, num($('ex-dur').value), $('ex-intensity').value); }
    });
    $('ex-type').addEventListener('change', function () {
      $('ex-dur').value = exDefaultDur(this.value);
      if ($('ex-detail-fields').style.display === 'block') $('ex-cal').value = exEstimateCal(this.value, num($('ex-dur').value), $('ex-intensity').value);
    });
    $('ex-dur').addEventListener('input', function () {
      if ($('ex-detail-fields').style.display === 'block') $('ex-cal').value = exEstimateCal($('ex-type').value, num(this.value), $('ex-intensity').value);
    });
    $('ex-intensity').addEventListener('change', function () {
      if ($('ex-detail-fields').style.display === 'block') $('ex-cal').value = exEstimateCal($('ex-type').value, num($('ex-dur').value), this.value);
    });
    $('ex-addtype').addEventListener('click', function () {
      var v = $('ex-newtype').value.trim(); if (!v) { toast('请输入类型名称', 'err'); return; }
      if (!state.exerciseCustomTypes) state.exerciseCustomTypes = [];
      if (state.exerciseCustomTypes.indexOf(v) < 0) { state.exerciseCustomTypes.push(v); saveState(); }
      $('ex-type').innerHTML = exTypeOptions(v); $('ex-type').value = v;
    });
    $('exSave').onclick = function () { saveExercise(rec); };
    $('exCancel').onclick = closeModal;
    showModal();
  }
  function saveExercise(old) {
    var type = $('ex-type').value;
    if (!type) { toast('请选择运动类型', 'err'); return; }
    var dur = num($('ex-dur').value);
    if (dur <= 0) { toast('时长须大于0', 'err'); return; }
    var detail = $('ex-detail-fields').style.display === 'block';
    var date = detail ? ($('ex-date').value || TODAY) : TODAY;
    var time = nowTime();
    var calories = detail ? num($('ex-cal').value) : exEstimateCal(type, dur, '中等');
    var intensity = detail ? $('ex-intensity').value : '中等';
    var feeling = detail ? $('ex-feeling').value.trim() : '';
    var note = detail ? $('ex-note').value.trim() : '';
    var rec = { id: editing.exercise || uid(), date: date, time: time, type: type, cat: exCatOf(type), duration: dur, calories: calories, intensity: intensity, feeling: feeling, note: note };
    if (editing.exercise) { var i = state.exercise.findIndex(function (x) { return x.id === editing.exercise; }); if (i >= 0) state.exercise[i] = rec; }
    else state.exercise.push(rec);
    saveState(); closeModal(); renderExercise(); renderOverview();
    syncBadges(true); checkGoalCelebration();
    toast(detail ? '已保存' : pickEncourage(), 'ok');
  }
  function openExerciseGoalModal() {
    var g = (state.exerciseGoal && state.exerciseGoal.monthDays) || 15;
    var rt = (state.exerciseGoal && state.exerciseGoal.remindTime) || '';
    $('modalTitle').textContent = '月度运动目标';
    $('modalBody').innerHTML =
      '<label>月度目标天数<input type="number" id="exg-days" min="1" value="' + g + '"/></label>' +
      '<label>每日提醒时间<small style="color:var(--muted)">（可选）</small><input type="time" id="exg-time" value="' + esc(rt) + '"/></label>' +
      '<div class="modal-actions"><button class="btn primary" id="exgSave">保存</button><button class="btn ghost" id="exgCancel">取消</button></div>';
    $('exgSave').onclick = function () {
      var d = num($('exg-days').value); if (d <= 0) { toast('目标需大于0', 'err'); return; }
      state.exerciseGoal = { monthDays: d, remindTime: $('exg-time').value || '' };
      saveState(); closeModal(); renderExercise(); renderOverview(); syncBadges(true); checkGoalCelebration();
      toast('目标已更新', 'ok');
    };
    $('exgCancel').onclick = closeModal;
    showModal();
  }
  function exInit() {
    if (!state.exerciseGoal) state.exerciseGoal = { monthDays: 15, remindTime: '' };
    if (!state.exerciseCustomTypes) state.exerciseCustomTypes = [];
    if (!state.exerciseBadgesSeen) state.exerciseBadgesSeen = [];
    syncBadges(false);
  }

  /* ============ 模块3：好好吃饭（三模式合一） ============ */
  var MEAL_TYPES = ['早餐', '午餐', '晚餐', '加餐'];
  var MEAL_ICON = { '早餐': '🌅', '午餐': '🍚', '晚餐': '🌙', '加餐': '🍎' };
  var MOODS = ['😊', '😐', '😋', '🤔', '😅'];
  var TAG_SUGGEST = ['#家常菜', '#探店', '#甜品', '#健康餐', '#外卖', '#轻食', '#聚餐', '#早餐'];

  var mealMode = 'diary';     // diary / nutrition / check
  var diaryView = 'wall';     // wall / timeline / calendar
  var checkView = 'today';    // today / calendar
  var mealCalMonth = null;
  var mealSelDate = null;

  function mealSorted() {
    return state.meal.slice().sort(function (a, b) {
      if (a.date !== b.date) return a.date < b.date ? 1 : -1;
      return (a.time || '') < (b.time || '') ? 1 : -1;
    });
  }
  // 某日四餐打卡状态： true已打卡 / 'skip'跳过 / false待打卡
  function mealStatusOf(date) {
    var out = {};
    MEAL_TYPES.forEach(function (t) { out[t] = false; });
    state.meal.forEach(function (m) {
      if (m.date !== date) return;
      if (m.skip) out[m.mealType] = 'skip';
      else out[m.mealType] = true;
    });
    return out;
  }
  function mealStreak() {
    var n = 0, d = TODAY;
    while (true) {
      var st = mealStatusOf(d);
      var anyDone = MEAL_TYPES.some(function (t) { return st[t] === true; });
      if (!anyDone) break;
      n++; d = dateAdd(d, -1);
      if (n > 2000) break;
    }
    return n;
  }
  // 今日打卡：至少一餐已打卡即为达标
  function todayMealKcal(date) {
    date = date || TODAY;
    var sum = 0;
    state.meal.forEach(function (m) { if (m.date === date && !m.skip) sum += num(m.kcal); });
    return sum;
  }

  function renderMeal() {
    renderMealCheckin();
    // 模式 Tab 高亮
    document.querySelectorAll('[data-mtab]').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-mtab') === mealMode); });
    document.querySelectorAll('[data-mpane]').forEach(function (p) { p.hidden = (p.getAttribute('data-mpane') !== mealMode); });
    document.querySelectorAll('[data-dview]').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-dview') === diaryView); });
    document.querySelectorAll('[data-cview]').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-cview') === checkView); });
    if (mealMode === 'diary') renderDiary();
    else if (mealMode === 'nutrition') renderNutrition();
    else renderCheck();
  }

  // ---- 顶部打卡状态条 ----
  function renderMealCheckin() {
    var st = mealStatusOf(TODAY);
    var streak = mealStreak();
    var cards = MEAL_TYPES.map(function (t) {
      var s = st[t], cls = s === true ? 'done' : (s === 'skip' ? 'skip' : 'wait'), txt = s === true ? '已打卡 ✅' : (s === 'skip' ? '已跳过 ⬜' : '待打卡 ⏳');
      return '<div class="ci-meal ' + cls + '" data-cmeal="' + t + '"><div class="ic">' + MEAL_ICON[t] + '</div><div class="nm">' + t + '</div><div class="st">' + txt + '</div></div>';
    }).join('');
    $('mealCheckin').innerHTML =
      '<div class="ci-kcal-row"><span class="ci-label">今日已记录 <b>' + todayMealRecords() + '</b> 餐 · 摄入 <b>' + todayMealKcal() + '</b> kcal</span>' +
      (streak > 0 ? '<span class="ci-streak">🔥 连续打卡 ' + streak + ' 天</span>' : '') + '</div>' +
      '<div class="ci-meals">' + cards + '</div>';
    Array.prototype.forEach.call($('mealCheckin').querySelectorAll('[data-cmeal]'), function (el) {
      el.onclick = function () { mealMode = 'check'; checkView = 'today'; openMealModal(null, el.getAttribute('data-cmeal')); };
    });
  }
  function todayMealRecords() {
    return state.meal.filter(function (m) { return m.date === TODAY && !m.skip; }).length;
  }

  // ---- 模式一：美食日记 ----
  function renderDiary() {
    var box = $('diaryContent');
    var recs = mealSorted();
    if (!recs.length) { box.innerHTML = emptyState('🍽️', '今天还没记录，去吃一顿好的吧'); return; }
    if (diaryView === 'wall') renderPhotoWall(box, recs);
    else if (diaryView === 'timeline') renderMealTimeline(box, recs);
    else renderMealCalendar(box, 'diary');
  }
  function renderPhotoWall(box, recs) {
    var withPhoto = recs.filter(function (r) { return r.photo; });
    if (!withPhoto.length) { box.innerHTML = '<div class="muted-tip" style="padding:10px 0">还没有照片记录，切到「时间线」看看，或记录时上传一张美食照 📸</div>'; return; }
    box.innerHTML = '<div class="meal-photo-wall">' + withPhoto.map(function (r) {
      return '<div class="pw-item" data-id="' + r.id + '"><img src="' + esc(r.photo) + '"/>' +
        '<div class="pw-meta"><div class="pw-food">' + esc(r.food) + '</div><div class="pw-sub">' + esc(r.mealType) + ' · ' + esc(r.date.slice(5)) + '</div></div></div>';
    }).join('') + '</div>';
    bindMealCards(box);
  }
  function renderMealTimeline(box, recs) {
    var html = '', curDay = '';
    recs.forEach(function (r) {
      if (r.date !== curDay) { curDay = r.date; html += '<div class="meal-tl-day">📅 ' + r.date + '</div>'; }
      var tags = '';
      if (r.kcal) tags += '<span class="tag kcal">' + Math.round(r.kcal) + ' kcal</span>';
      if (r.mood) tags += '<span class="tag">' + r.mood + '</span>';
      var chips = (r.tags || []).map(function (t) { return '<span class="chip">' + esc(t) + '</span>'; }).join('');
      var subs = [];
      if (r.place) subs.push('📍 ' + esc(r.place));
      if (r.note) subs.push(esc(r.note));
      html += '<div class="meal-tl-item" data-id="' + r.id + '">' +
        '<div class="meal-tl-card"><div class="row1"><span class="food">' + esc(r.food) + '</span>' +
        '<span class="tag">' + esc(r.mealType) + '</span>' + tags + '<span class="tag">' + (r.time || '') + '</span></div>' +
        (subs.length ? '<div class="place">' + subs.join(' · ') + '</div>' : '') +
        (chips ? '<div class="chips">' + chips + '</div>' : '') +
        (r.photo ? '<img class="photo" src="' + esc(r.photo) + '" data-photo="1"/>' : '') +
        '<div class="ops"><button class="icon-btn" data-act="edit" data-mod="meal" title="编辑">✏️</button>' +
        '<button class="icon-btn" data-act="del" data-mod="meal" title="删除">🗑️</button></div></div></div>';
    });
    box.innerHTML = '<div class="meal-tl">' + html + '</div>';
    bindMealCards(box);
  }
  function renderMealCalendar(box, from) {
    if (!mealCalMonth) mealCalMonth = TODAY.slice(0, 7);
    var year = +mealCalMonth.slice(0, 4), month = +mealCalMonth.slice(5, 7) - 1;
    var dows = ['日', '一', '二', '三', '四', '五', '六'];
    var html = '<div class="w-cal-head"><button class="btn ghost sm" id="mCalPrev">◀</button><span>' + year + '年' + (month + 1) + '月</span><button class="btn ghost sm" id="mCalNext">▶</button></div>';
    html += '<div class="w-cal" style="grid-template-columns:repeat(7,1fr)">';
    dows.forEach(function (d) { html += '<div class="meal-cal-dow">' + d + '</div>'; });
    var first = new Date(year, month, 1), startDow = first.getDay();
    var daysInM = new Date(year, month + 1, 0).getDate();
    for (var i = 0; i < startDow; i++) html += '<div class="meal-cal-cell empty"></div>';
    var grouped = {};
    state.meal.forEach(function (m) { if (m.date.slice(0, 7) === mealCalMonth && !m.skip) { (grouped[m.date] = grouped[m.date] || []).push(m); } });
    for (var dd = 1; dd <= daysInM; dd++) {
      var ds = year + '-' + pad(month + 1) + '-' + pad(dd);
      var recs = grouped[ds] || [];
      var isToday = ds === TODAY;
      if (!recs.length) { html += '<div class="meal-cal-cell empty' + (isToday ? ' today' : '') + '"><span class="cd">' + dd + '</span></div>'; continue; }
      var cover = recs.find(function (r) { return r.photo; }) || recs[0];
      html += '<div class="meal-cal-cell' + (isToday ? ' today' : '') + '" data-cdate="' + ds + '">' +
        (cover.photo ? '<img src="' + esc(cover.photo) + '"/>' : '<div style="color:var(--muted);font-size:11px;align-self:center">' + recs.length + '餐</div>') +
        '<span class="cd">' + dd + '</span></div>';
    }
    html += '</div>';
    box.innerHTML = html;
    var prev = $('mCalPrev'), next = $('mCalNext');
    if (prev) prev.onclick = function () { mealCalMonth = monthAdd(mealCalMonth, -1); renderMeal(); };
    if (next) next.onclick = function () { mealCalMonth = monthAdd(mealCalMonth, 1); renderMeal(); };
    Array.prototype.forEach.call(box.querySelectorAll('[data-cdate]'), function (el) {
      el.onclick = function () { mealSelDate = el.getAttribute('data-cdate'); mealMode = 'diary'; diaryView = 'timeline'; renderMeal(); };
    });
  }
  function bindMealCards(box) {
    Array.prototype.forEach.call(box.querySelectorAll('[data-id]'), function (el) {
      el.onclick = function (e) {
        if (e.target.closest('[data-act]')) return;
        if (e.target.hasAttribute('data-photo')) { openPhotoModal(e.target.getAttribute('src')); return; }
        var id = el.getAttribute('data-id');
        openMealModal(id);
      };
    });
    Array.prototype.forEach.call(box.querySelectorAll('[data-photo]'), function (img) {
      img.onclick = function (e) { e.stopPropagation(); openPhotoModal(img.getAttribute('src')); };
    });
  }

  // ---- 模式二：营养追踪 ----
  function renderNutrition() {
    var tg = state.mealTarget;
    var sum = { kcal: 0, protein: 0, carb: 0, fat: 0 };
    state.meal.forEach(function (m) { if (m.date === TODAY && !m.skip) { sum.kcal += num(m.kcal); sum.protein += num(m.protein); sum.carb += num(m.carb); sum.fat += num(m.fat); } });
    var gap = tg.kcal > 0 ? (tg.kcal - sum.kcal) : 0;
    $('nutriKcal').innerHTML = '<span class="big">' + Math.round(sum.kcal) + '</span><span class="small">/ ' + (tg.kcal > 0 ? Math.round(tg.kcal) + ' kcal' : '未设目标') +
      '</span>' + (tg.kcal > 0 ? '<span class="gap">' + (gap >= 0 ? '还可 ' + Math.round(gap) : '超 ' + Math.round(-gap)) + ' kcal</span>' : '');
    // 营养素占比环形图
    var macro = [sum.protein, sum.carb, sum.fat];
    var total = macro[0] + macro[1] + macro[2];
    var colors = ['#94B0A0', '#D4B8A8', '#E0B389'];
    var labels = ['蛋白质', '碳水', '脂肪'];
    $('nutriDonut').innerHTML = total > 0
      ? donutHTML(total ? macro : [1, 1, 1], colors, labels, Math.round(total) + ' g')
      : emptyState('🍎', '今天还没有营养数据');
    // 近 7 日热量趋势
    renderNutriTrend();
    // 本月按餐别分布
    renderNutriByMeal();
  }
  function renderNutriTrend() {
    var box = $('nutriTrend');
    var days = [];
    for (var i = 6; i >= 0; i--) days.push(dateAdd(TODAY, -i));
    var data = days.map(function (d) {
      var k = 0; state.meal.forEach(function (m) { if (m.date === d && !m.skip) k += num(m.kcal); });
      return { label: d.slice(5), v: k };
    });
    var maxV = Math.max.apply(null, data.map(function (d) { return d.v; }).concat([1]));
    if (maxV === 0) { box.innerHTML = '<div class="muted-tip">近 7 日暂无热量记录</div>'; return; }
    var W = 320, H = 150, mL = 34, mR = 10, mT = 10, mB = 24, pw = W - mL - mR, ph = H - mT - mB;
    function X(i) { return mL + (data.length === 1 ? pw / 2 : pw * i / (data.length - 1)); }
    function Y(v) { return mT + ph * (1 - v / maxV); }
    var path = data.map(function (d, i) { return (i ? 'L' : 'M') + X(i).toFixed(1) + ' ' + Y(d.v).toFixed(1); }).join(' ');
    var area = path + ' L' + X(data.length - 1).toFixed(1) + ' ' + (mT + ph) + ' L' + X(0).toFixed(1) + ' ' + (mT + ph) + ' Z';
    var dots = data.map(function (d, i) { return '<circle cx="' + X(i).toFixed(1) + '" cy="' + Y(d.v).toFixed(1) + '" r="3" fill="#D4B8A8"><title>' + d.label + ' · ' + Math.round(d.v) + ' kcal</title></circle>'; }).join('');
    var xl = data.map(function (d, i) { return '<text x="' + X(i).toFixed(1) + '" y="' + (H - 8) + '" text-anchor="middle" class="w-chart-tip">' + d.label + '</text>'; }).join('');
    box.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="xMidYMid meet" role="img">' +
      '<defs><linearGradient id="mealTrend" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#D4B8A8" stop-opacity="0.18"/><stop offset="100%" stop-color="#D4B8A8" stop-opacity="0.02"/></linearGradient></defs>' +
      '<path d="' + area + '" fill="url(#mealTrend)"/><path d="' + path + '" fill="none" stroke="#D4B8A8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>' +
      dots + xl + '</svg>';
  }
  function renderNutriByMeal() {
    var box = $('nutriByMeal');
    var ym = TODAY.slice(0, 7);
    var sums = {}; MEAL_TYPES.forEach(function (t) { sums[t] = 0; });
    state.meal.forEach(function (m) { if (m.date.slice(0, 7) === ym && !m.skip) sums[m.mealType] += num(m.kcal); });
    var total = MEAL_TYPES.reduce(function (a, t) { return a + sums[t]; }, 0);
    if (total === 0) { box.innerHTML = '<div class="muted-tip">本月暂无热量记录</div>'; return; }
    box.innerHTML = MEAL_TYPES.map(function (t) {
      var v = sums[t], pct = Math.round(v / total * 100);
      return '<div style="display:flex;align-items:center;gap:10px;margin:8px 0">' +
        '<span style="width:42px;font-size:12px;color:var(--muted)">' + t + '</span>' +
        '<div style="flex:1;height:6px;border-radius:3px;background:#F0EDEA;overflow:hidden"><div style="height:100%;width:' + pct + '%;background:#D4B8A8;border-radius:3px"></div></div>' +
        '<span style="width:86px;font-size:12px;color:var(--text);text-align:right">' + Math.round(v) + ' kcal · ' + pct + '%</span></div>';
    }).join('');
  }
  // 通用环形图
  function donutHTML(values, colors, labels, center) {
    var total = values.reduce(function (a, b) { return a + b; }, 0);
    var W = 200, H = 200, cx = 100, cy = 100, r = 70, sw = 26;
    var circ = 2 * Math.PI * r;
    var off = 0, arcs = '';
    values.forEach(function (v, i) {
      var frac = total > 0 ? v / total : 1 / values.length;
      var len = frac * circ;
      arcs += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' + colors[i] + '" stroke-width="' + sw + '" ' +
        'stroke-dasharray="' + len.toFixed(2) + ' ' + (circ - len).toFixed(2) + '" stroke-dashoffset="' + (-off).toFixed(2) + '" transform="rotate(-90 ' + cx + ' ' + cy + ')"/>';
      off += len;
    });
    var legend = labels.map(function (l, i) { return '<span class="lg"><span class="dot" style="background:' + colors[i] + '"></span>' + l + ' ' + Math.round(values[i]) + 'g</span>'; }).join('');
    return '<div style="display:flex;flex-direction:column;align-items:center">' +
      '<svg viewBox="0 0 ' + W + ' ' + H + '" style="width:170px;height:170px">' + arcs +
      '<text x="' + cx + '" y="' + (cy - 4) + '" text-anchor="middle" style="font-size:15px;fill:var(--primary-deep);font-weight:550">' + (center || '') + '</text>' +
      '<text x="' + cx + '" y="' + (cy + 14) + '" text-anchor="middle" style="font-size:11px;fill:var(--muted)">总营养</text></svg>' +
      '<div class="rep-legend" style="justify-content:center">' + legend + '</div></div>';
  }

  // ---- 模式三：轻打卡 ----
  function renderCheck() {
    var box = $('checkContent');
    if (checkView === 'today') {
      var st = mealStatusOf(TODAY);
      $('checkTip').textContent = '轻点卡片即可打卡 / 跳过，记录「吃了没」';
      box.innerHTML = '<div class="check-today-grid">' + MEAL_TYPES.map(function (t) {
        var s = st[t], cls = s === true ? 'done' : (s === 'skip' ? 'skip' : '');
        var txt = s === true ? '已打卡 ✅' : (s === 'skip' ? '已跳过 ⬜' : '点我打卡 ⏳');
        var rec = state.meal.find(function (m) { return m.date === TODAY && m.mealType === t; });
        var sub = rec && rec.food ? '🍽️ ' + esc(rec.food) : '还没记录吃了什么';
        return '<div class="check-card ' + cls + '" data-cmeal="' + t + '"><div class="ch-top"><span class="ch-ic">' + MEAL_ICON[t] + '</span><span class="ch-status">' + txt + '</span></div><div class="ch-sub">' + sub + '</div></div>';
      }).join('') + '</div>';
      Array.prototype.forEach.call(box.querySelectorAll('[data-cmeal]'), function (el) {
        el.onclick = function () { openMealModal(null, el.getAttribute('data-cmeal')); };
      });
    } else {
      renderCheckCalendar(box);
    }
  }
  function renderCheckCalendar(box) {
    if (!mealCalMonth) mealCalMonth = TODAY.slice(0, 7);
    var year = +mealCalMonth.slice(0, 4), month = +mealCalMonth.slice(5, 7) - 1;
    var dows = ['日', '一', '二', '三', '四', '五', '六'];
    var html = '<div class="w-cal-head"><button class="btn ghost sm" id="mCalPrev">◀</button><span>' + year + '年' + (month + 1) + '月</span><button class="btn ghost sm" id="mCalNext">▶</button></div>';
    html += '<div class="check-grid" style="grid-template-columns:repeat(7,1fr)">';
    dows.forEach(function (d) { html += '<div class="cg-dow">' + d + '</div>'; });
    var first = new Date(year, month, 1), startDow = first.getDay();
    var daysInM = new Date(year, month + 1, 0).getDate();
    for (var i = 0; i < startDow; i++) html += '<div class="cg-cell empty"></div>';
    for (var dd = 1; dd <= daysInM; dd++) {
      var ds = year + '-' + pad(month + 1) + '-' + pad(dd);
      var st = mealStatusOf(ds), done = 0;
      MEAL_TYPES.forEach(function (t) { if (st[t] === true) done++; });
      var isToday = ds === TODAY;
      var dotCls = done === 4 ? 'full' : (done > 0 ? 'part' : '');
      html += '<div class="cg-cell' + (isToday ? ' today' : '') + '" data-cdate="' + ds + '"><span>' + dd + '</span>' +
        (dotCls ? '<span class="cg-dot ' + dotCls + '"></span>' : '') + '</div>';
    }
    html += '</div>';
    $('checkTip').textContent = '🟢 四餐全打卡 · 🟠 部分打卡';
    box.innerHTML = html;
    var prev = $('mCalPrev'), next = $('mCalNext');
    if (prev) prev.onclick = function () { mealCalMonth = monthAdd(mealCalMonth, -1); renderMeal(); };
    if (next) next.onclick = function () { mealCalMonth = monthAdd(mealCalMonth, 1); renderMeal(); };
    Array.prototype.forEach.call(box.querySelectorAll('[data-cdate]'), function (el) {
      el.onclick = function () { mealSelDate = el.getAttribute('data-cdate'); mealMode = 'diary'; diaryView = 'timeline'; renderMeal(); };
    });
  }

  // ---- 记录浮窗（三模式通用） ----
  /* 内置食物库：每份单位下的热量/蛋白质/碳水/脂肪
     单位尽量采用日常口径（碗/个/杯/片/根/份），数量 × 基数 = 总营养 */
  var MEAL_FOOD_LIB = {
    // 主食
    '米饭（1碗）': { unit: '碗', kcal: 230, protein: 4, carb: 51, fat: 0.5 },
    '蛋炒饭（1碗）': { unit: '碗', kcal: 350, protein: 8, carb: 50, fat: 12 },
    '白粥（1碗）': { unit: '碗', kcal: 90, protein: 2, carb: 20, fat: 0 },
    '小米粥（1碗）': { unit: '碗', kcal: 100, protein: 3, carb: 20, fat: 1 },
    '馒头': { unit: '个', kcal: 220, protein: 7, carb: 45, fat: 1 },
    '花卷': { unit: '个', kcal: 230, protein: 7, carb: 46, fat: 1.5 },
    '肉包': { unit: '个', kcal: 220, protein: 7, carb: 32, fat: 8 },
    '酱肉包': { unit: '个', kcal: 235, protein: 8, carb: 33, fat: 8.5 },
    '菜包': { unit: '个', kcal: 180, protein: 5, carb: 35, fat: 3 },
    '豆沙包': { unit: '个', kcal: 210, protein: 5, carb: 40, fat: 5 },
    '烧麦': { unit: '个', kcal: 180, protein: 4, carb: 25, fat: 7 },
    '小笼包': { unit: '个', kcal: 50, protein: 2, carb: 6, fat: 2 },
    '饺子': { unit: '个', kcal: 45, protein: 2, carb: 6, fat: 1.5 },
    '馄饨（1碗）': { unit: '碗', kcal: 280, protein: 12, carb: 40, fat: 8 },
    '面条（1碗）': { unit: '碗', kcal: 280, protein: 9, carb: 58, fat: 2 },
    '牛肉面（1碗）': { unit: '碗', kcal: 480, protein: 22, carb: 60, fat: 16 },
    '番茄鸡蛋面（1碗）': { unit: '碗', kcal: 420, protein: 14, carb: 62, fat: 12 },
    '炸酱面（1碗）': { unit: '碗', kcal: 520, protein: 16, carb: 70, fat: 18 },
    '凉皮（1份）': { unit: '份', kcal: 320, protein: 6, carb: 55, fat: 8 },
    '煎饼果子': { unit: '个', kcal: 380, protein: 10, carb: 55, fat: 14 },
    '油条': { unit: '根', kcal: 270, protein: 5, carb: 30, fat: 15 },
    '全麦面包': { unit: '片', kcal: 75, protein: 3, carb: 13, fat: 1 },
    '吐司': { unit: '片', kcal: 80, protein: 2, carb: 15, fat: 1.5 },
    '燕麦片': { unit: '50g', kcal: 190, protein: 7, carb: 33, fat: 4 },
    '玉米': { unit: '根', kcal: 150, protein: 5, carb: 32, fat: 2 },
    '红薯': { unit: '个', kcal: 130, protein: 2, carb: 30, fat: 0.5 },
    '紫薯': { unit: '个', kcal: 140, protein: 2, carb: 32, fat: 0.5 },
    '土豆泥': { unit: '份', kcal: 140, protein: 2, carb: 20, fat: 6 },
    '方便面（1包）': { unit: '包', kcal: 480, protein: 10, carb: 65, fat: 20 },
    // 肉蛋奶
    '鸡蛋': { unit: '个', kcal: 78, protein: 6, carb: 0.6, fat: 5 },
    '水煮蛋': { unit: '个', kcal: 78, protein: 6, carb: 0.6, fat: 5 },
    '荷包蛋': { unit: '个', kcal: 120, protein: 7, carb: 1, fat: 10 },
    '茶叶蛋': { unit: '个', kcal: 80, protein: 6, carb: 1, fat: 6 },
    '煎蛋': { unit: '个', kcal: 140, protein: 7, carb: 1, fat: 12 },
    '鸡胸肉': { unit: '100g', kcal: 165, protein: 31, carb: 0, fat: 3.6 },
    '鸡腿': { unit: '个', kcal: 180, protein: 18, carb: 0, fat: 12 },
    '鸡翅': { unit: '个', kcal: 90, protein: 7, carb: 0, fat: 7 },
    '猪肉': { unit: '100g', kcal: 250, protein: 20, carb: 0, fat: 19 },
    '红烧肉': { unit: '100g', kcal: 350, protein: 15, carb: 5, fat: 28 },
    '排骨': { unit: '100g', kcal: 280, protein: 18, carb: 0, fat: 23 },
    '牛肉': { unit: '100g', kcal: 250, protein: 26, carb: 0, fat: 17 },
    '酱牛肉': { unit: '100g', kcal: 200, protein: 28, carb: 2, fat: 9 },
    '鱼肉': { unit: '100g', kcal: 120, protein: 20, carb: 0, fat: 4 },
    '虾': { unit: '100g', kcal: 100, protein: 20, carb: 0, fat: 1 },
    '香肠': { unit: '根', kcal: 220, protein: 8, carb: 2, fat: 20 },
    '培根': { unit: '2片', kcal: 90, protein: 6, carb: 1, fat: 7 },
    '牛奶': { unit: '盒（250ml）', kcal: 150, protein: 8, carb: 12, fat: 8 },
    '酸奶': { unit: '盒', kcal: 120, protein: 4, carb: 16, fat: 4 },
    '豆浆': { unit: '杯', kcal: 80, protein: 6, carb: 5, fat: 3 },
    '奶酪': { unit: '片', kcal: 80, protein: 5, carb: 1, fat: 6 },
    // 蔬菜豆制品
    '豆腐': { unit: '100g', kcal: 80, protein: 8, carb: 2, fat: 5 },
    '麻婆豆腐': { unit: '100g', kcal: 120, protein: 7, carb: 5, fat: 8 },
    '番茄炒蛋': { unit: '100g', kcal: 130, protein: 5, carb: 5, fat: 10 },
    '炒青菜': { unit: '100g', kcal: 60, protein: 2, carb: 5, fat: 4 },
    '凉拌黄瓜': { unit: '100g', kcal: 40, protein: 1, carb: 4, fat: 2 },
    '土豆丝': { unit: '100g', kcal: 90, protein: 2, carb: 15, fat: 3 },
    '茄子煲': { unit: '100g', kcal: 120, protein: 3, carb: 10, fat: 8 },
    '蒜蓉西兰花': { unit: '100g', kcal: 55, protein: 4, carb: 6, fat: 2 },
    '炒豆角': { unit: '100g', kcal: 70, protein: 2, carb: 10, fat: 3 },
    '冬瓜汤': { unit: '碗', kcal: 50, protein: 2, carb: 6, fat: 2 },
    '紫菜蛋花汤': { unit: '碗', kcal: 70, protein: 5, carb: 5, fat: 4 },
    '海带丝': { unit: '100g', kcal: 45, protein: 2, carb: 6, fat: 1 },
    '木耳炒蛋': { unit: '100g', kcal: 110, protein: 6, carb: 5, fat: 8 },
    // 水果
    '苹果': { unit: '个', kcal: 95, protein: 0.5, carb: 25, fat: 0.3 },
    '香蕉': { unit: '根', kcal: 105, protein: 1.3, carb: 27, fat: 0.4 },
    '橙子': { unit: '个', kcal: 62, protein: 1.2, carb: 15, fat: 0.2 },
    '猕猴桃': { unit: '个', kcal: 55, protein: 1, carb: 13, fat: 0.5 },
    '葡萄': { unit: '100g', kcal: 69, protein: 0.7, carb: 18, fat: 0.2 },
    '西瓜': { unit: '100g', kcal: 30, protein: 0.6, carb: 8, fat: 0.2 },
    '草莓': { unit: '100g', kcal: 32, protein: 0.7, carb: 8, fat: 0.3 },
    '蓝莓': { unit: '100g', kcal: 57, protein: 0.7, carb: 14, fat: 0.3 },
    '芒果': { unit: '个', kcal: 135, protein: 1.5, carb: 35, fat: 0.5 },
    '桃子': { unit: '个', kcal: 60, protein: 1, carb: 14, fat: 0.4 },
    '梨': { unit: '个', kcal: 100, protein: 0.4, carb: 25, fat: 0.3 },
    '火龙果': { unit: '个', kcal: 120, protein: 2, carb: 29, fat: 0.5 },
    '哈密瓜': { unit: '100g', kcal: 34, protein: 0.5, carb: 8, fat: 0.2 },
    // 饮品零食
    '可乐': { unit: '罐（330ml）', kcal: 140, protein: 0, carb: 35, fat: 0 },
    '雪碧': { unit: '罐（330ml）', kcal: 130, protein: 0, carb: 34, fat: 0 },
    '橙汁': { unit: '杯', kcal: 120, protein: 2, carb: 28, fat: 0 },
    '美式咖啡': { unit: '杯', kcal: 5, protein: 0.3, carb: 0, fat: 0 },
    '拿铁': { unit: '中杯', kcal: 150, protein: 6, carb: 12, fat: 9 },
    '奶茶': { unit: '中杯', kcal: 300, protein: 3, carb: 45, fat: 12 },
    '柠檬水': { unit: '杯', kcal: 80, protein: 0, carb: 20, fat: 0 },
    '薯片': { unit: '小包', kcal: 260, protein: 3, carb: 25, fat: 17 },
    '巧克力': { unit: '块', kcal: 150, protein: 2, carb: 16, fat: 9 },
    '饼干': { unit: '3片', kcal: 120, protein: 2, carb: 18, fat: 5 },
    '蛋糕': { unit: '块', kcal: 350, protein: 5, carb: 45, fat: 17 },
    '冰淇淋': { unit: '个', kcal: 200, protein: 3, carb: 24, fat: 11 },
    '瓜子': { unit: '50g', kcal: 280, protein: 10, carb: 10, fat: 24 },
    '坚果': { unit: '30g', kcal: 180, protein: 5, carb: 6, fat: 16 },
    // 常见菜肴/外卖
    '宫保鸡丁': { unit: '100g', kcal: 180, protein: 14, carb: 8, fat: 10 },
    '鱼香肉丝': { unit: '100g', kcal: 170, protein: 10, carb: 12, fat: 9 },
    '糖醋里脊': { unit: '100g', kcal: 220, protein: 10, carb: 20, fat: 11 },
    '酸菜鱼': { unit: '份', kcal: 450, protein: 30, carb: 15, fat: 28 },
    '麻辣香锅': { unit: '份', kcal: 650, protein: 22, carb: 55, fat: 38 },
    '黄焖鸡米饭': { unit: '份', kcal: 650, protein: 28, carb: 75, fat: 25 },
    '盖浇饭（荤）': { unit: '份', kcal: 600, protein: 20, carb: 75, fat: 22 },
    '盖浇饭（素）': { unit: '份', kcal: 450, protein: 10, carb: 75, fat: 15 },
    '兰州拉面': { unit: '碗', kcal: 500, protein: 18, carb: 70, fat: 16 },
    '汉堡': { unit: '个', kcal: 540, protein: 25, carb: 42, fat: 28 },
    '麦辣鸡翅': { unit: '对', kcal: 180, protein: 12, carb: 10, fat: 11 },
    '薯条（中）': { unit: '份', kcal: 320, protein: 4, carb: 41, fat: 16 },
    '披萨': { unit: '角', kcal: 280, protein: 12, carb: 32, fat: 12 },
    '寿司': { unit: '个', kcal: 45, protein: 2, carb: 8, fat: 1 },
    '三明治': { unit: '个', kcal: 350, protein: 15, carb: 35, fat: 16 },
    '沙拉': { unit: '份', kcal: 120, protein: 4, carb: 12, fat: 7 },
    '关东煮': { unit: '份', kcal: 250, protein: 10, carb: 25, fat: 12 },
    // ===== 扩充：面条/粉类 =====
    '番茄牛腩面（1碗）': { unit: '碗', kcal: 520, protein: 24, carb: 62, fat: 18 },
    '担担面（1碗）': { unit: '碗', kcal: 450, protein: 14, carb: 55, fat: 18 },
    '阳春面（1碗）': { unit: '碗', kcal: 320, protein: 8, carb: 58, fat: 6 },
    '重庆小面（1碗）': { unit: '碗', kcal: 480, protein: 12, carb: 60, fat: 20 },
    '螺蛳粉（1份）': { unit: '份', kcal: 550, protein: 12, carb: 80, fat: 18 },
    '桂林米粉（1碗）': { unit: '碗', kcal: 380, protein: 10, carb: 58, fat: 10 },
    '过桥米线（1碗）': { unit: '碗', kcal: 450, protein: 18, carb: 60, fat: 14 },
    '酸辣粉（1碗）': { unit: '碗', kcal: 400, protein: 8, carb: 65, fat: 12 },
    '热干面（1碗）': { unit: '碗', kcal: 420, protein: 12, carb: 62, fat: 13 },
    '凉面（1份）': { unit: '份', kcal: 300, protein: 7, carb: 52, fat: 8 },
    '炒河粉（1盘）': { unit: '盘', kcal: 500, protein: 14, carb: 72, fat: 17 },
    '炒米粉（1盘）': { unit: '盘', kcal: 480, protein: 13, carb: 68, fat: 16 },
    '扬州炒饭（1碗）': { unit: '碗', kcal: 420, protein: 12, carb: 58, fat: 15 },
    '炒饭（1碗）': { unit: '碗', kcal: 380, protein: 9, carb: 55, fat: 13 },
    '煲仔饭（1份）': { unit: '份', kcal: 700, protein: 24, carb: 82, fat: 26 },
    '咖喱饭（1份）': { unit: '份', kcal: 600, protein: 18, carb: 75, fat: 24 },
    '蛋包饭（1份）': { unit: '份', kcal: 580, protein: 20, carb: 72, fat: 21 },
    '皮蛋瘦肉粥（1碗）': { unit: '碗', kcal: 200, protein: 10, carb: 28, fat: 6 },
    '八宝粥（1碗）': { unit: '碗', kcal: 180, protein: 4, carb: 38, fat: 2 },
    // ===== 扩充：肉类菜肴 =====
    '回锅肉（100g）': { unit: '100g', kcal: 380, protein: 16, carb: 6, fat: 32 },
    '糖醋排骨（100g）': { unit: '100g', kcal: 350, protein: 16, carb: 18, fat: 24 },
    '牛腩（100g）': { unit: '100g', kcal: 220, protein: 24, carb: 2, fat: 14 },
    '肥牛卷（100g）': { unit: '100g', kcal: 260, protein: 18, carb: 1, fat: 21 },
    '羊肉串（1串）': { unit: '串', kcal: 150, protein: 10, carb: 2, fat: 12 },
    '烤羊排（100g）': { unit: '100g', kcal: 290, protein: 22, carb: 1, fat: 23 },
    '红烧鱼（100g）': { unit: '100g', kcal: 180, protein: 18, carb: 6, fat: 10 },
    '水煮鱼（1份）': { unit: '份', kcal: 480, protein: 38, carb: 15, fat: 30 },
    '烤鱼（1份）': { unit: '份', kcal: 550, protein: 40, carb: 12, fat: 38 },
    '白灼虾（100g）': { unit: '100g', kcal: 95, protein: 20, carb: 0, fat: 1 },
    '油焖大虾（100g）': { unit: '100g', kcal: 180, protein: 18, carb: 6, fat: 11 },
    '麻辣小龙虾（1份）': { unit: '份', kcal: 500, protein: 45, carb: 20, fat: 28 },
    '可乐鸡翅（100g）': { unit: '100g', kcal: 200, protein: 14, carb: 14, fat: 11 },
    '鸭腿': { unit: '个', kcal: 240, protein: 18, carb: 0, fat: 18 },
    '鸭脖': { unit: '根', kcal: 160, protein: 14, carb: 2, fat: 11 },
    '卤味拼盘（1份）': { unit: '份', kcal: 350, protein: 28, carb: 8, fat: 24 },
    '火腿肠': { unit: '根', kcal: 150, protein: 5, carb: 8, fat: 12 },
    '午餐肉（100g）': { unit: '100g', kcal: 280, protein: 10, carb: 8, fat: 24 },
    '咸鸭蛋': { unit: '个', kcal: 170, protein: 13, carb: 3, fat: 12 },
    '皮蛋': { unit: '个', kcal: 140, protein: 11, carb: 3, fat: 10 },
    '鸡翅中': { unit: '个', kcal: 120, protein: 11, carb: 0, fat: 8 },
    '鸡爪': { unit: '个', kcal: 76, protein: 10, carb: 0, fat: 4 },
    // ===== 扩充：家常菜 =====
    '青椒肉丝（100g）': { unit: '100g', kcal: 150, protein: 14, carb: 6, fat: 9 },
    '木须肉（100g）': { unit: '100g', kcal: 140, protein: 12, carb: 5, fat: 9 },
    '地三鲜（100g）': { unit: '100g', kcal: 120, protein: 3, carb: 12, fat: 7 },
    '干煸豆角（100g）': { unit: '100g', kcal: 140, protein: 4, carb: 10, fat: 10 },
    '干锅花菜（100g）': { unit: '100g', kcal: 110, protein: 3, carb: 8, fat: 8 },
    '酸辣白菜（100g）': { unit: '100g', kcal: 70, protein: 2, carb: 6, fat: 4 },
    '醋溜白菜（100g）': { unit: '100g', kcal: 65, protein: 2, carb: 5, fat: 4 },
    '蚝油生菜（100g）': { unit: '100g', kcal: 65, protein: 2, carb: 5, fat: 4.5 },
    '拍黄瓜（1份）': { unit: '份', kcal: 60, protein: 2, carb: 6, fat: 3 },
    '酸辣土豆丝（100g）': { unit: '100g', kcal: 100, protein: 2, carb: 16, fat: 4 },
    '鱼香茄子（100g）': { unit: '100g', kcal: 130, protein: 3, carb: 12, fat: 9 },
    '红烧茄子（100g）': { unit: '100g', kcal: 140, protein: 3, carb: 12, fat: 10 },
    '西红柿炒鸡蛋（100g）': { unit: '100g', kcal: 125, protein: 5, carb: 5, fat: 9 },
    // ===== 扩充：快餐/外卖 =====
    '沙县小吃拌云吞（1份）': { unit: '份', kcal: 420, protein: 16, carb: 56, fat: 15 },
    '隆江猪脚饭（1份）': { unit: '份', kcal: 750, protein: 32, carb: 85, fat: 30 },
    '叉烧饭（1份）': { unit: '份', kcal: 680, protein: 28, carb: 80, fat: 26 },
    '卤肉饭（1份）': { unit: '份', kcal: 650, protein: 26, carb: 78, fat: 27 },
    '烧腊双拼饭（1份）': { unit: '份', kcal: 720, protein: 32, carb: 82, fat: 28 },
    '麦当劳巨无霸（1个）': { unit: '个', kcal: 560, protein: 26, carb: 46, fat: 30 },
    '肯德基全家桶（1份）': { unit: '份', kcal: 1800, protein: 85, carb: 140, fat: 95 },
    '炸鸡（1块）': { unit: '块', kcal: 290, protein: 18, carb: 12, fat: 22 },
    '手抓饼（1个）': { unit: '个', kcal: 420, protein: 8, carb: 52, fat: 20 },
    '烤冷面（1份）': { unit: '份', kcal: 450, protein: 12, carb: 58, fat: 20 },
    '章鱼小丸子（1份）': { unit: '份', kcal: 280, protein: 6, carb: 32, fat: 14 },
    '炸串（1份）': { unit: '份', kcal: 380, protein: 16, carb: 28, fat: 24 },
    '钵钵鸡（1份）': { unit: '份', kcal: 320, protein: 22, carb: 12, fat: 22 },
    '冒菜（1份）': { unit: '份', kcal: 450, protein: 18, carb: 28, fat: 28 },
    '麻辣烫（1份）': { unit: '份', kcal: 500, protein: 20, carb: 55, fat: 24 },
    '串串香（1份）': { unit: '份', kcal: 550, protein: 28, carb: 45, fat: 30 },
    '火锅（人均）': { unit: '人', kcal: 900, protein: 45, carb: 50, fat: 55 },
    '烧烤（人均）': { unit: '人', kcal: 850, protein: 50, carb: 40, fat: 55 },
    '烤串（1串）': { unit: '串', kcal: 120, protein: 8, carb: 3, fat: 10 },
    // ===== 扩充：汤类 =====
    '番茄蛋汤（1碗）': { unit: '碗', kcal: 85, protein: 5, carb: 6, fat: 5 },
    '青菜豆腐汤（1碗）': { unit: '碗', kcal: 80, protein: 6, carb: 5, fat: 4 },
    '排骨汤（1碗）': { unit: '碗', kcal: 180, protein: 14, carb: 3, fat: 13 },
    '鸡汤（1碗）': { unit: '碗', kcal: 120, protein: 10, carb: 2, fat: 8 },
    '酸辣汤（1碗）': { unit: '碗', kcal: 150, protein: 8, carb: 12, fat: 8 },
    '胡辣汤（1碗）': { unit: '碗', kcal: 200, protein: 10, carb: 25, fat: 7 },
    '牛肉粉丝汤（1碗）': { unit: '碗', kcal: 280, protein: 16, carb: 32, fat: 10 },
    '西湖牛肉羹（1碗）': { unit: '碗', kcal: 160, protein: 12, carb: 10, fat: 9 },
    // ===== 扩充：豆制品 =====
    '老豆腐（100g）': { unit: '100g', kcal: 76, protein: 8, carb: 3, fat: 4.5 },
    '嫩豆腐（100g）': { unit: '100g', kcal: 60, protein: 6, carb: 3, fat: 3 },
    '豆皮（100g）': { unit: '100g', kcal: 220, protein: 20, carb: 8, fat: 14 },
    '腐竹（100g）': { unit: '100g', kcal: 460, protein: 44, carb: 22, fat: 26 },
    '千张（100g）': { unit: '100g', kcal: 230, protein: 23, carb: 8, fat: 14 },
    '油豆腐（100g）': { unit: '100g', kcal: 245, protein: 17, carb: 8, fat: 18 },
    '臭豆腐（1份）': { unit: '份', kcal: 280, protein: 12, carb: 12, fat: 20 },
    '毛血旺（1份）': { unit: '份', kcal: 420, protein: 25, carb: 18, fat: 28 },
    // ===== 扩充：水果 =====
    '葡萄（100g）': { unit: '100g', kcal: 69, protein: 0.7, carb: 18, fat: 0.2 },
    '西瓜（100g）': { unit: '100g', kcal: 30, protein: 0.6, carb: 8, fat: 0.2 },
    '草莓（100g）': { unit: '100g', kcal: 32, protein: 0.7, carb: 8, fat: 0.3 },
    '蓝莓（100g）': { unit: '100g', kcal: 57, protein: 0.7, carb: 14, fat: 0.3 },
    '柚子（2瓣）': { unit: '份', kcal: 60, protein: 0.8, carb: 14, fat: 0.2 },
    '柠檬（1个）': { unit: '个', kcal: 20, protein: 0.5, carb: 6, fat: 0.1 },
    '菠萝（100g）': { unit: '100g', kcal: 50, protein: 0.5, carb: 13, fat: 0.1 },
    '樱桃（100g）': { unit: '100g', kcal: 46, protein: 1, carb: 11, fat: 0.2 },
    '荔枝（100g）': { unit: '100g', kcal: 66, protein: 0.9, carb: 16, fat: 0.4 },
    '山竹（100g）': { unit: '100g', kcal: 73, protein: 0.7, carb: 18, fat: 0.3 },
    '榴莲（100g）': { unit: '100g', kcal: 147, protein: 2.5, carb: 27, fat: 3.5 },
    '椰子水（1杯）': { unit: '杯', kcal: 45, protein: 2, carb: 8, fat: 0.5 },
    // ===== 扩充：饮品 =====
    '奶茶（全糖）': { unit: '杯', kcal: 450, protein: 4, carb: 65, fat: 18 },
    '奶茶（半糖）': { unit: '杯', kcal: 320, protein: 3, carb: 48, fat: 12 },
    '珍珠奶茶（1杯）': { unit: '杯', kcal: 500, protein: 5, carb: 78, fat: 18 },
    '卡布奇诺（1杯）': { unit: '杯', kcal: 130, protein: 6, carb: 12, fat: 6 },
    '雪碧（1罐）': { unit: '罐', kcal: 135, protein: 0, carb: 34, fat: 0 },
    '椰汁（1盒）': { unit: '盒', kcal: 100, protein: 2, carb: 18, fat: 3 },
    '王老吉（1罐）': { unit: '罐', kcal: 70, protein: 0, carb: 17, fat: 0 },
    '冰红茶（1瓶）': { unit: '瓶', kcal: 120, protein: 0, carb: 30, fat: 0 },
    '啤酒（1罐）': { unit: '罐', kcal: 150, protein: 1.5, carb: 13, fat: 0 },
    '红酒（1杯）': { unit: '杯', kcal: 125, protein: 0.1, carb: 3, fat: 0 },
    '功能饮料（1瓶）': { unit: '瓶', kcal: 80, protein: 0, carb: 20, fat: 0 },
    // ===== 扩充：零食 =====
    '薯片（1袋）': { unit: '袋', kcal: 300, protein: 3, carb: 35, fat: 16 },
    '辣条（1包）': { unit: '包', kcal: 200, protein: 4, carb: 22, fat: 10 },
    '饼干（1包）': { unit: '包', kcal: 280, protein: 4, carb: 38, fat: 12 },
    '奥利奥（1包）': { unit: '包', kcal: 220, protein: 2, carb: 34, fat: 9 },
    '薯条（1份）': { unit: '份', kcal: 340, protein: 5, carb: 45, fat: 16 },
    '油饼': { unit: '张', kcal: 320, protein: 6, carb: 38, fat: 16 },
    '豆浆油条套餐': { unit: '套', kcal: 360, protein: 11, carb: 36, fat: 18 },
    '奶油蛋糕（1块）': { unit: '块', kcal: 320, protein: 4, carb: 38, fat: 17 },
    '水饺（10个）': { unit: '份', kcal: 450, protein: 20, carb: 60, fat: 15 },
    '抄手（1碗）': { unit: '碗', kcal: 300, protein: 14, carb: 42, fat: 9 }
  };
  function openMealModal(id, presetMeal) {
    editing.meal = id || null;
    var rec = id ? state.meal.find(function (m) { return m.id === id; }) : null;
    var presetMode = mealMode === 'check' ? 'check' : (rec ? (rec.kcal ? 'nutrition' : 'diary') : mealMode);
    var now = new Date();
    $('modalTitle').textContent = rec ? '编辑饮食记录' : '记录一餐';
    $('modalBody').innerHTML =
      '<div class="meal-mode-tabs" id="mModes">' +
      '<button data-mm="diary"' + (presetMode === 'diary' ? ' class="active"' : '') + '><span class="seg-ico">📸</span>美食日记</button>' +
      '<button data-mm="nutrition"' + (presetMode === 'nutrition' ? ' class="active"' : '') + '><span class="seg-ico">📊</span>营养追踪</button>' +
      '<button data-mm="check"' + (presetMode === 'check' ? ' class="active"' : '') + '><span class="seg-ico">✅</span>轻打卡</button></div>' +
      '<label>用餐日期 *<input type="date" id="mm-date" value="' + (rec ? rec.date : TODAY) + '"/></label>' +
      '<label>餐别 *<select id="mm-meal">' + MEAL_TYPES.map(function (t) { return '<option' + (t === (rec ? rec.mealType : (presetMeal || '午餐')) ? ' selected' : '') + '>' + t + '</option>'; }).join('') + '</select></label>' +
      '<label>食物名称 *<input type="text" id="mm-food" placeholder="如 番茄牛腩面" value="' + (rec ? esc(rec.food || '') : '') + '" list="mealFoodList"/><datalist id="mealFoodList">' + Object.keys(MEAL_FOOD_LIB).map(function (f) { return '<option value="' + f + '"></option>'; }).join('') + '</datalist></label>' +
      '<label>心情<select id="mm-mood">' + MOODS.map(function (m) { return '<option' + (m === (rec && rec.mood) ? ' selected' : '') + '>' + m + '</option>'; }).join('') + '</select></label>' +
      '<div id="mmDiaryFields">' +
      '<label>用餐地点<input type="text" id="mm-place" placeholder="家里 / 公司食堂 / XX餐厅" value="' + (rec ? esc(rec.place || '') : '') + '"/></label>' +
      '<label>食物照片<input type="file" id="mm-photo" accept="image/*" /></label>' +
      (rec && rec.photo ? '<img class="meal-photo-preview" src="' + esc(rec.photo) + '"/>' : '') +
      '<div class="tag-input-row" id="mmTags"></div>' +
      '<div class="tag-suggest" id="mmTagSuggest"></div>' +
      '<label class="full">文字笔记<textarea id="mm-note" rows="2" placeholder="味道、感受、故事…">' + (rec ? esc(rec.note || '') : '') + '</textarea></label>' +
      '<div class="modal-actions"><button class="btn primary" id="mmSave">保存</button><button class="btn ghost" id="mmCancel">取消</button></div>' +
      '</div>' +
      '<div id="mmNutriFields" hidden>' +
      '<input type="hidden" id="mm-portion" value="' + (rec ? esc(rec.portion || '') : '') + '"/>' +
      '<div class="grid-2"><label>热量(kcal)<input type="number" id="mm-kcal" min="0" step="1" placeholder="可自动带入" value="' + (rec ? (rec.kcal || '') : '') + '"/></label>' +
      '<div class="meal-qty-wrap"><label>份量/重量<input type="number" id="mm-qty" min="0" step="0.1" placeholder="1" value="' + (rec && rec.qty ? rec.qty : '') + '"/></label><span class="meal-unit" id="mm-unit">' + (rec && rec.unit ? esc(rec.unit) : '') + '</span></div></div>' +
      '<div class="grid-2"><label>蛋白质(g)<input type="number" id="mm-protein" min="0" step="0.1" value="' + (rec ? (rec.protein || '') : '') + '"/></label>' +
      '<label>碳水(g)<input type="number" id="mm-carb" min="0" step="0.1" value="' + (rec ? (rec.carb || '') : '') + '"/></label></div>' +
      '<div class="grid-2"><label>脂肪(g)<input type="number" id="mm-fat" min="0" step="0.1" value="' + (rec ? (rec.fat || '') : '') + '"/></label>' +
      '<button class="link-btn" id="mmAuto" type="button">↧ 从食物库带入营养</button></div>' +
      '<div class="modal-actions"><button class="btn primary" id="mmSaveNutri">保存</button><button class="btn ghost" id="mmCancelNutri">取消</button></div></div>' +
      '<div id="mmCheckFields" hidden style="margin-top:8px"><div class="muted-tip">轻打卡：仅记录「吃了没」，可填一句备注</div>' +
      '<label class="full">备注<input type="text" id="mm-check-note" placeholder="吃了什么（可选）" value="' + (rec ? esc(rec.note || '') : '') + '"/></label>' +
      '<div class="radio-row" style="margin-top:6px"><label class="rb"><input type="radio" name="mm-skip" value="no"' + (!rec || !rec.skip ? ' checked' : '') + '/> 已吃</label>' +
      '<label class="rb"><input type="radio" name="mm-skip" value="yes"' + (rec && rec.skip ? ' checked' : '') + '/> 跳过</label></div>' +
      '<div class="modal-actions"><button class="btn primary" id="mmSaveCheck">保存</button><button class="btn ghost" id="mmCancelCheck">取消</button></div></div>';
    // 模式切换
    var mTags = (rec && rec.tags) ? rec.tags.slice() : [];
    function syncMode(m) {
      document.querySelectorAll('#mModes button').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-mm') === m); });
      $('mmDiaryFields').hidden = (m !== 'diary');
      $('mmNutriFields').hidden = (m !== 'nutrition');
      $('mmCheckFields').hidden = (m !== 'check');
    }
    document.querySelectorAll('#mModes button').forEach(function (b) {
      b.onclick = function () { syncMode(b.getAttribute('data-mm')); };
    });
    syncMode(presetMode);
    // 标签
    function renderTags() {
      $('mmTags').innerHTML = mTags.map(function (t, i) { return '<span class="tag">' + esc(t) + '<span class="x" data-i="' + i + '">×</span></span>'; }).join('') +
        '<input type="text" id="mmTagInput" placeholder="+ 标签" style="border:none;background:transparent;width:70px;font-family:var(--font);font-size:12px;outline:none"/>';
      var inp = $('mmTagInput');
      inp.onkeydown = function (e) { if (e.key === 'Enter' && inp.value.trim()) { mTags.push(inp.value.trim()); renderTags(); } };
      Array.prototype.forEach.call($('mmTags').querySelectorAll('.x'), function (x) { x.onclick = function () { mTags.splice(+x.getAttribute('data-i'), 1); renderTags(); }; });
    }
    renderTags();
    $('mmTagSuggest').innerHTML = TAG_SUGGEST.map(function (t) { return '<span class="s" data-t="' + esc(t) + '">' + t + '</span>'; }).join('');
    Array.prototype.forEach.call($('mmTagSuggest').querySelectorAll('.s'), function (s) {
      s.onclick = function () { var t = s.getAttribute('data-t'); if (mTags.indexOf(t) < 0) { mTags.push(t); renderTags(); } };
    });
    // 自动带入营养（数量 × 食物库每份基数）
    function applyMealFood(forceToast) {
      var food = $('mm-food').value.trim();
      var lib = MEAL_FOOD_LIB[food];
      if (!lib) return false;
      var qty = num($('mm-qty').value);
      if (qty <= 0) qty = 1;
      $('mm-qty').value = qty;
      $('mm-unit').textContent = lib.unit;
      $('mm-kcal').value = Math.round(lib.kcal * qty * 10) / 10;
      $('mm-protein').value = Math.round(lib.protein * qty * 10) / 10;
      $('mm-carb').value = Math.round(lib.carb * qty * 10) / 10;
      $('mm-fat').value = Math.round(lib.fat * qty * 10) / 10;
      if (forceToast) toast('已带入营养数据', 'ok');
      return true;
    }
    $('mmAuto').onclick = function () {
      if (!applyMealFood(true)) toast('食物库里没有「' + $('mm-food').value.trim() + '」，可手动填写', 'warn');
    };
    $('mm-food').onchange = function () { applyMealFood(false); };
    $('mm-qty').oninput = function () { applyMealFood(false); };
    $('mmSave').onclick = function () { saveMeal(rec, mTags); };
    $('mmCancel').onclick = closeModal;
    $('mmSaveNutri').onclick = function () { saveMeal(rec, mTags); };
    $('mmCancelNutri').onclick = closeModal;
    $('mmSaveCheck').onclick = function () { saveMeal(rec, mTags); };
    $('mmCancelCheck').onclick = closeModal;
    showModal();
  }
  function saveMeal(rec, mTags) {
    var date = $('mm-date').value || TODAY;
    var mealType = $('mm-meal').value;
    var food = $('mm-food').value.trim();
    var m = document.querySelector('#mModes button.active').getAttribute('data-mm');
    if (m !== 'check' && !food) { toast('请填写食物名称', 'err'); return; }
    var skip = false;
    if (m === 'check') { skip = radioVal('mm-skip') === 'yes'; }
    var qty = $('mm-qty') ? num($('mm-qty').value) : 0;
    var unit = $('mm-unit') ? $('mm-unit').textContent.trim() : '';
    var portionHidden = $('mm-portion') ? $('mm-portion').value.trim() : '';
    var obj = {
      id: editing.meal || uid(), date: date, mealType: mealType, food: food,
      mood: $('mm-mood').value, place: $('mm-place') ? $('mm-place').value.trim() : '',
      note: (m === 'check' ? $('mm-check-note').value.trim() : $('mm-note').value.trim()),
      photo: rec ? (rec.photo || '') : '', tags: mTags.slice(),
      portion: (qty > 0 && unit) ? (qty + unit) : portionHidden,
      qty: qty, unit: unit,
      kcal: num($('mm-kcal').value), protein: num($('mm-protein').value), carb: num($('mm-carb').value), fat: num($('mm-fat').value),
      skip: skip
    };
    var file = $('mm-photo') && $('mm-photo').files[0];
    var finish = function () {
      if (editing.meal) { var i = state.meal.findIndex(function (x) { return x.id === editing.meal; }); if (i >= 0) state.meal[i] = obj; }
      else state.meal.push(obj);
      saveState(); closeModal(); renderMeal(); renderOverview();
      toast(skip ? '已标记跳过' : '✨ 又记录了一餐', 'ok');
    };
    if (file) {
      var reader = new FileReader();
      reader.onload = function () { compressPhoto(reader.result, function (b64) { obj.photo = b64; finish(); }); };
      reader.onerror = finish;
      reader.readAsDataURL(file);
    } else finish();
  }
  // 营养目标设定
  function openMealTargetModal() {
    var t = state.mealTarget;
    $('modalTitle').textContent = '热量 & 营养目标';
    $('modalBody').innerHTML =
      '<label>每日热量目标(kcal) *<input type="number" id="mt-kcal" min="0" step="10" value="' + (t.kcal || '') + '"/></label>' +
      '<div class="grid-2"><label>蛋白质目标(g)<input type="number" id="mt-protein" min="0" step="1" value="' + (t.protein || '') + '"/></label>' +
      '<label>碳水目标(g)<input type="number" id="mt-carb" min="0" step="1" value="' + (t.carb || '') + '"/></label></div>' +
      '<div class="grid-2"><label>脂肪目标(g)<input type="number" id="mt-fat" min="0" step="1" value="' + (t.fat || '') + '"/></label></div>' +
      '<div class="modal-actions"><button class="btn primary" id="mtSave">保存</button><button class="btn ghost" id="mtCancel">取消</button></div>';
    $('mtSave').onclick = function () {
      var k = num($('mt-kcal').value);
      if (k <= 0) { toast('请填写热量目标', 'err'); return; }
      state.mealTarget = { kcal: k, protein: num($('mt-protein').value), carb: num($('mt-carb').value), fat: num($('mt-fat').value) };
      saveState(); closeModal(); renderMeal();
      toast('目标已保存', 'ok');
    };
    $('mtCancel').onclick = closeModal;
    showModal();
  }
  // 旧数据迁移（旧版用 healthy 字段，新版无该字段）
  function migrateMeal() {
    var need = state.meal.some(function (m) { return m.healthy !== undefined; });
    if (need) {
      state.meal = state.meal.map(function (m) {
        return { id: m.id || uid(), date: m.date, mealType: m.mealType || '午餐', food: m.food || '', mood: '😊', place: '', note: m.note || '', photo: '', tags: [], portion: '', kcal: 0, protein: 0, carb: 0, fat: 0, skip: false };
      });
      saveState();
    }
  }

  /* ============ 模块4：体重管理 ============ */
  var weightTab = 'trend';
  // var wCalMonth = null;     // 已删除日历功能
  var wSelDate = null;         // 列表选中日期
  var wTrendRange = 'month';

  // 按日期升序返回记录（同一天按时间）
  function weightSorted() {
    return state.weight.slice().sort(function (a, b) {
      if (a.date !== b.date) return a.date < b.date ? -1 : 1;
      return (a.time || '') < (b.time || '') ? -1 : 1;
    });
  }
  // 按日期分组的"每日最新体重"（最近一条）
  function weightByDateDesc() {
    var map = {};
    weightSorted().forEach(function (w) { map[w.date] = w; }); // 升序覆盖 => 同日最后一条
    return Object.keys(map).sort(function (a, b) { return a < b ? 1 : -1; }).map(function (d) { return map[d]; });
  }
  function latestWeight() { return weightByDateDesc()[0] || null; }
  function weightOnDate(d) { return state.weight.filter(function (w) { return w.date === d; }); }

  // 连续记录天数：从今天往前，连续有记录的天数（今日未记录则从昨日往前）
  function streakDays() {
    var start = weightOnDate(TODAY).length ? TODAY : (weightOnDate(YESTERDAY).length ? YESTERDAY : null);
    if (!start) return 0;
    var n = 0, cur = start;
    var dates = {}; state.weight.forEach(function (w) { dates[w.date] = 1; });
    while (dates[cur]) { n++; cur = dateAdd(cur, -1); }
    return n;
  }

  // 情感化反馈文案
  function feelMessage() {
    var latest = latestWeight();
    if (!latest) return { txt: '📝 今天还没有记录体重哦，去称一下吗？', cls: 'warn' };
    var todayRec = weightOnDate(TODAY);
    var stk = streakDays();
    var target = num(state.weightTarget.target);
    // 今日尚未记录
    if (!todayRec.length) return { txt: '📝 今天还没有记录体重哦，去称一下吗？', cls: 'warn' };
    // 达到目标
    if (target > 0 && num(latest.weight) <= target) return { txt: '🎊 恭喜达成目标体重！你太厉害了！', cls: 'good' };
    // 接近目标 ≤1kg
    if (target > 0 && (num(latest.weight) - target) <= 1 && (num(latest.weight) - target) > 0) return { txt: '🎉 距离目标只有' + (num(latest.weight) - target).toFixed(1) + 'kg了，太棒了！', cls: 'good' };
    // 连续记录 ≥7 天
    if (stk >= 7) return { txt: '🌟 已连续记录' + stk + '天，好习惯正在养成！', cls: 'good' };
    // 与昨日比较
    var yRec = weightOnDate(YESTERDAY);
    if (yRec.length) {
      var yw = yRec[yRec.length - 1].weight;
      var diff = num(latest.weight) - num(yw);
      if (diff < 0) return { txt: '😊 比昨天轻了' + Math.abs(diff).toFixed(1) + 'kg，继续保持哦！', cls: 'good' };
      if (diff > 0) return { txt: '💪 比昨天重了' + diff.toFixed(1) + 'kg，今天多动一动吧！', cls: 'warn' };
    }
    return { txt: '🌟 记录已保存，继续加油！', cls: 'mid' };
  }

  // 徽章判定
  function computeBadges() {
    var badges = [];
    var recs = weightSorted();
    if (recs.length) badges.push({ icon: '🏅', name: '首次记录' });
    var stk = streakDays();
    if (stk >= 7) badges.push({ icon: '📅', name: '连续7天' });
    if (stk >= 30) badges.push({ icon: '📅', name: '连续30天' });
    if (stk >= 100) badges.push({ icon: '📅', name: '连续100天' });
    var target = num(state.weightTarget.target);
    var latest = latestWeight();
    if (target > 0 && latest && num(latest.weight) <= target) badges.push({ icon: '🎯', name: '达成目标' });
    var startW = num(state.weightTarget.startWeight || (recs[0] ? recs[0].weight : 0));
    if (latest && startW > 0 && (startW - num(latest.weight)) >= 5) badges.push({ icon: '⬇️', name: '减重5kg' });
    if (latest && startW > 0 && (startW - num(latest.weight)) >= 10) badges.push({ icon: '⬇️', name: '减重10kg' });
    return badges;
  }

  function renderWeight() {
    // 摘要卡片
    var latest = latestWeight();
    var target = num(state.weightTarget.target);
    var startW = num(state.weightTarget.startWeight);
    if (!startW && recs0()) startW = weightSorted()[0].weight;
    function recs0() { return weightSorted()[0]; }
    var assetInfo = '';
    var m1 = { lbl: '最新体重', val: latest ? latest.weight.toFixed(1) + ' kg' : '暂无' };
    var m2 = { lbl: '目标体重', val: target > 0 ? '<span class="click" id="wTargetClick">' + target.toFixed(1) + ' kg</span>' : '<span class="click" id="wTargetClick">未设定</span>' };
    var progHtml = '';
    if (latest) {
      var diffNeed = target > 0 ? (num(latest.weight) - target) : 0;
      var diffLost = startW > 0 ? (startW - num(latest.weight)) : 0;
      var m3 = diffNeed > 0 ? { lbl: '还需减', val: diffNeed.toFixed(1) + ' kg' } : { lbl: '已减', val: diffLost.toFixed(1) + ' kg' };
      if (target > 0 && startW > 0) {
        var pct = startW > target ? Math.max(0, Math.min(100, (diffLost / (startW - target)) * 100)) : 0;
        var col = pct < 50 ? '#E0A82E' : pct < 80 ? '#D4B8A8' : pct < 100 ? '#2D7D46' : '#D4AF37';
        progHtml = '<div class="w-progress"><div class="txt">已减 ' + diffLost.toFixed(1) + 'kg / 目标 ' + (startW - target).toFixed(1) + 'kg · 完成 ' + pct.toFixed(0) + '%</div><div class="bar"><div class="fill" style="width:' + pct + '%;background:' + col + '"></div></div></div>';
      }
      assetInfo = '<div class="w-metrics">' + [m1, m2, m3, { lbl: '连续记录', val: streakDays() + ' 天' }].map(function (m) {
        return '<div class="w-metric"><div class="lbl">' + m.lbl + '</div><div class="val">' + m.val + '</div></div>';
      }).join('') + '</div>';
    } else {
      assetInfo = '<div class="w-metrics">' + [m1, m2, { lbl: '还需减', val: '—' }, { lbl: '连续记录', val: '0 天' }].map(function (m) {
        return '<div class="w-metric"><div class="lbl">' + m.lbl + '</div><div class="val">' + m.val + '</div></div>';
      }).join('') + '</div>';
    }
    var feel = feelMessage();
    $('wSummary').innerHTML = assetInfo +
      '<div class="w-feel ' + feel.cls + '">' + feel.txt + '</div>' + progHtml;
    var tClick = $('wTargetClick'); if (tClick) tClick.onclick = openTargetModal;

    // 徽章
    var badges = computeBadges();
    $('wBadges').innerHTML = badges.length ? badges.map(function (b) { return '<span class="badge">' + b.icon + ' ' + b.name + '</span>'; }).join('') : '';

    // 切到对应子视图
    document.querySelectorAll('[data-wtab]').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-wtab') === weightTab); });
    document.querySelectorAll('[data-wpane]').forEach(function (p) { p.hidden = p.getAttribute('data-wpane') !== weightTab; });
    if (weightTab === 'trend') renderWeightChart();
    else renderWeightList();
  }

  // ---- 趋势图（SVG）----
  function renderWeightChart() {
    var box = $('wChart');
    var pts = weightSorted();
    if (pts.length < 3) {
      box.innerHTML = emptyState('📊', pts.length ? '再多记录几天，趋势图就会出现了' : '还没有体重记录，开始记录你的第一组数据吧');
      return;
    }
    var today = new Date();
    var now = today.getTime();
    var day = 86400000;
    var range = wTrendRange;
    var buckets = [];
    if (range === 'week') { for (var i = 6; i >= 0; i--) { var d = new Date(now - i * day); buckets.push({ key: fmtDate(d), label: (d.getMonth() + 1) + '/' + d.getDate() }); } }
    else if (range === 'month') { for (var i = 29; i >= 0; i--) { var d = new Date(now - i * day); buckets.push({ key: fmtDate(d), label: (d.getMonth() + 1) + '/' + d.getDate() }); } }
    else if (range === 'quarter') { for (var i = 12; i >= 0; i--) { var d = new Date(now - i * 7 * day); buckets.push({ key: fmtDate(d), label: (d.getMonth() + 1) + '/' + d.getDate() }); } }
    else if (range === 'year') { for (var i = 11; i >= 0; i--) { var d = new Date(now); d.setMonth(d.getMonth() - i); buckets.push({ key: d.getFullYear() + '-' + pad(d.getMonth() + 1), label: (d.getMonth() + 1) + '月' }); } }
    else {
      // 全部：按周
      var all = pts.map(function (p) { return p.date; });
      var minD = all[0], maxD = all[all.length - 1];
      var cur = new Date(minD); cur.setDate(1);
      while (fmtDate(cur) <= maxD) { buckets.push({ key: cur.getFullYear() + '-' + pad(cur.getMonth() + 1), label: (cur.getMonth() + 1) + '月' }); cur.setMonth(cur.getMonth() + 1); }
    }
    // 聚合：取该桶内最后一条记录的体重
    function valForKey(k) {
      var rec = null;
      state.weight.forEach(function (w) {
        var wk = range === 'year' || range === 'all' ? w.date.slice(0, 7) : w.date;
        if (wk === k) rec = w;
      });
      return rec ? num(rec.weight) : null;
    }
    var data = buckets.map(function (b) { return { x: b.key, label: b.label, v: valForKey(b.key) }; });
    data = data.filter(function (d) { return d.v !== null; });
    if (data.length < 2) { box.innerHTML = emptyState('📊', '再多记录几天，趋势图就会出现了'); return; }

    var allv = data.map(function (d) { return d.v; });
    var minV = Math.min.apply(null, allv), maxV = Math.max.apply(null, allv);
    var target = num(state.weightTarget.target), startW = num(state.weightTarget.startWeight);
    var lo = minV, hi = maxV;
    if (target > 0) { lo = Math.min(lo, target); hi = Math.max(hi, target); }
    if (startW > 0) { lo = Math.min(lo, startW); hi = Math.max(hi, startW); }
    var padV = (hi - lo) * 0.15 + 0.5; lo -= padV; hi += padV;
    if (hi === lo) hi = lo + 1;

    var W = 720, H = 280, mL = 44, mR = 16, mT = 16, mB = 34;
    var pw = W - mL - mR, ph = H - mT - mB;
    function X(i) { return mL + (data.length === 1 ? pw / 2 : pw * i / (data.length - 1)); }
    function Y(v) { return mT + ph * (1 - (v - lo) / (hi - lo)); }
    var path = data.map(function (d, i) { return (i ? 'L' : 'M') + X(i).toFixed(1) + ' ' + Y(d.v).toFixed(1); }).join(' ');
    var area = path + ' L' + X(data.length - 1).toFixed(1) + ' ' + (mT + ph) + ' L' + X(0).toFixed(1) + ' ' + (mT + ph) + ' Z';
    var ylines = '';
    for (var g = 0; g <= 4; g++) { var gv = lo + (hi - lo) * g / 4; ylines += '<line x1="' + mL + '" y1="' + (mT + ph * g / 4).toFixed(1) + '" x2="' + (W - mR) + '" y2="' + (mT + ph * g / 4).toFixed(1) + '" stroke="#ECE8E4" stroke-width="1"/>'; ylines += '<text x="' + (mL - 6) + '" y="' + (mT + ph * g / 4 + 3).toFixed(1) + '" text-anchor="end" class="w-chart-tip">' + gv.toFixed(1) + '</text>'; }
    var xlabels = data.map(function (d, i) { return '<text x="' + X(i).toFixed(1) + '" y="' + (H - 12) + '" text-anchor="middle" class="w-chart-tip">' + d.label + '</text>'; }).join('');
    var dots = data.map(function (d, i) { return '<circle cx="' + X(i).toFixed(1) + '" cy="' + Y(d.v).toFixed(1) + '" r="3.5" fill="#D4B8A8" data-d="' + d.x + '"><title>' + d.x + ' · ' + d.v.toFixed(1) + ' kg</title></circle>'; }).join('');
    var tLine = '', sLine = '';
    if (target > 0 && target >= lo && target <= hi) tLine = '<line x1="' + mL + '" y1="' + Y(target).toFixed(1) + '" x2="' + (W - mR) + '" y2="' + Y(target).toFixed(1) + '" stroke="#8A8A8A" stroke-width="1.2" stroke-dasharray="6 4"/><text x="' + (W - mR) + '" y="' + (Y(target) - 4).toFixed(1) + '" text-anchor="end" class="w-chart-tip">目标 ' + target.toFixed(1) + '</text>';
    if (startW > 0 && startW >= lo && startW <= hi) sLine = '<line x1="' + mL + '" y1="' + Y(startW).toFixed(1) + '" x2="' + (W - mR) + '" y2="' + Y(startW).toFixed(1) + '" stroke="#CFC9C3" stroke-width="1.2" stroke-dasharray="4 4"/><text x="' + mL + '" y="' + (Y(startW) - 4).toFixed(1) + '" class="w-chart-tip">起始 ' + startW.toFixed(1) + '</text>';
    box.innerHTML =
      '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="xMidYMid meet" role="img">' +
      '<defs><linearGradient id="wgrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#D4B8A8" stop-opacity="0.18"/><stop offset="100%" stop-color="#D4B8A8" stop-opacity="0.02"/></linearGradient></defs>' +
      ylines + area + '<path d="' + area + '" fill="url(#wgrad)" stroke="none"/>' +
      '<path d="' + path + '" fill="none" stroke="#D4B8A8" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>' +
      tLine + sLine + dots + xlabels + '</svg>';
    Array.prototype.forEach.call(box.querySelectorAll('circle'), function (c) {
      c.addEventListener('click', function () { wSelDate = c.getAttribute('data-d'); renderWeightList(); weightTab = 'list'; renderWeight(); });
    });
  }

  // ---- 列表（时间轴）----
  function renderWeightList() {
    var box = $('weightList');
    var recs = weightByDateDesc();
    if (wSelDate) recs = recs.filter(function (r) { return r.date === wSelDate; });
    if (!recs.length) { box.innerHTML = emptyState('⚖️', wSelDate ? '这一天还没有记录' : '还没有体重记录，点右下角开始吧'); $('wSelInfo').textContent = wSelDate ? '已筛选：' + wSelDate : ''; return; }
    var html = '<div class="w-timeline">';
    var curDay = '';
    recs.forEach(function (w) {
      if (w.date !== curDay) { curDay = w.date; var p = w.date.split('-'); html += '<div class="w-tl-day">— ' + p[0] + '年' + +p[1] + '月' + +p[2] + '日 —</div>'; }
      var subs = [];
      if (w.bodyfat) subs.push('体脂 ' + num(w.bodyfat).toFixed(1) + '%');
      var ms = w.measurements || {};
      ['waist', 'hip', 'chest', 'thigh', 'arm'].forEach(function (k) { if (ms[k]) subs.push({ waist: '腰围', hip: '臀围', chest: '胸围', thigh: '大腿围', arm: '手臂围' }[k] + ' ' + ms[k] + 'cm'); });
      html += '<div class="w-tl-item" data-id="' + w.id + '"><div class="time">🕐 ' + (w.time || '') + '</div>' +
        '<div class="rec-card"><div class="main">⚖️ ' + num(w.weight).toFixed(1) + ' kg</div>' +
        (subs.length ? '<div class="sub">' + subs.join(' · ') + '</div>' : '') +
        (w.note ? '<div class="note">📝 ' + esc(w.note) + '</div>' : '') +
        (w.photo ? '<img class="photo" src="' + esc(w.photo) + '" data-photo="1"/>' : '') +
        '<div class="ops"><button class="icon-btn" data-act="edit" data-mod="weight" title="编辑">✏️</button>' +
        '<button class="icon-btn" data-act="del" data-mod="weight" title="删除">🗑️</button></div></div></div>';
    });
    if (wSelDate) html += '<div style="text-align:center;margin-top:10px"><button class="btn ghost sm" id="wClearSel">查看全部记录</button></div>';
    html += '</div>';
    box.innerHTML = html;
    var clearBtn = $('wClearSel'); if (clearBtn) clearBtn.onclick = function () { wSelDate = null; renderWeight(); };
    Array.prototype.forEach.call(box.querySelectorAll('[data-photo]'), function (img) {
      img.onclick = function () { openPhotoModal(img.getAttribute('src')); };
    });
  }

  // ---- 记录浮窗 ----
  function openWeightModal(id) {
    editing.weight = id || null;
    var rec = id ? state.weight.find(function (w) { return w.id === id; }) : null;
    var now = new Date();
    $('modalTitle').textContent = rec ? '编辑体重记录' : '记录体重';
    var ms = rec && rec.measurements ? rec.measurements : {};
    $('modalBody').innerHTML =
      '<label>记录日期 *<input type="date" id="wm-date" value="' + (rec ? rec.date : TODAY) + '"/></label>' +
      '<label>记录时间 *<input type="time" id="wm-time" value="' + (rec ? (rec.time || '08:00') : pad(now.getHours()) + ':' + pad(now.getMinutes())) + '"/></label>' +
      '<label>体重(kg) *<input type="number" id="wm-weight" min="0.1" step="0.1" placeholder="如 52.5" value="' + (rec ? rec.weight : '') + '"/></label>' +
      '<label>体脂率(%)<input type="number" id="wm-bodyfat" min="0" step="0.1" placeholder="如 22.3" value="' + (rec ? (rec.bodyfat || '') : '') + '"/></label>' +
      '<button class="link-btn" id="wmMeasBtn" type="button">＋ 记录围度</button>' +
      '<div id="wmMeas" hidden style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:8px">' +
      ['腰围:waist', '臀围:hip', '胸围:chest', '大腿围:thigh', '手臂围:arm'].map(function (s) { var kv = s.split(':'); return '<label>' + kv[0] + '(cm)<input type="number" id="wm-' + kv[1] + '" step="0.1" value="' + (ms[kv[1]] || '') + '"/></label>'; }).join('') +
      '</div>' +
      '<label>体型照片<input type="file" id="wm-photo" accept="image/*" /></label>' +
      (rec && rec.photo ? '<div><img src="' + esc(rec.photo) + '" style="max-width:90px;max-height:90px;border-radius:8px;display:block;margin-top:6px"/></div>' : '') +
      '<label class="full">备注<input type="text" id="wm-note" placeholder="晨起空腹 / 姨妈期 / 昨晚聚餐" value="' + (rec ? esc(rec.note || '') : '') + '"/></label>' +
      '<div class="modal-actions"><button class="btn primary" id="wmSave">保存</button><button class="btn ghost" id="wmCancel">取消</button></div>';
    $('wmMeasBtn').onclick = function () { $('wmMeas').hidden = !$('wmMeas').hidden; };
    $('wmSave').onclick = function () { saveWeight(rec); };
    $('wmCancel').onclick = closeModal;
    showModal();
  }
  function saveWeight(rec) {
    var date = $('wm-date').value || TODAY;
    var time = $('wm-time').value || '08:00';
    var wt = num($('wm-weight').value);
    if (wt <= 0) { toast('体重须大于0', 'err'); return; }
    var ms = {};
    ['waist', 'hip', 'chest', 'thigh', 'arm'].forEach(function (k) { var v = num($('wm-' + k).value); if (v > 0) ms[k] = v; });
    var obj = {
      id: editing.weight || uid(), date: date, time: time, weight: wt,
      bodyfat: num($('wm-bodyfat').value), measurements: ms, note: $('wm-note').value.trim(), photo: rec ? (rec.photo || '') : ''
    };
    var file = $('wm-photo') && $('wm-photo').files[0];
    var finish = function () {
      if (editing.weight) { var i = state.weight.findIndex(function (x) { return x.id === editing.weight; }); if (i >= 0) state.weight[i] = obj; }
      else state.weight.push(obj);
      saveState(); closeModal(); renderWeight(); renderOverview();
      toast(feelMessage().txt, feelMessage().cls === 'warn' ? 'warn' : 'ok');
    };
    if (file) {
      var reader = new FileReader();
      reader.onload = function () { compressPhoto(reader.result, function (b64) { obj.photo = b64; finish(); }); };
      reader.onerror = finish;
      reader.readAsDataURL(file);
    } else finish();
  }
  // 前端压缩图片至 800px 宽以内
  function compressPhoto(dataUrl, cb) {
    try {
      var img = new Image();
      img.onload = function () {
        var scale = img.width > 800 ? 800 / img.width : 1;
        var c = document.createElement('canvas');
        c.width = Math.round(img.width * scale); c.height = Math.round(img.height * scale);
        c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
        cb(c.toDataURL('image/jpeg', 0.7));
      };
      img.onerror = function () { cb(dataUrl); };
      img.src = dataUrl;
    } catch (e) { cb(dataUrl); }
  }
  function openPhotoModal(src) {
    $('modalTitle').textContent = '体型照片';
    $('modalBody').innerHTML = '<img src="' + esc(src) + '" style="width:100%;border-radius:10px"/>';
    $('modalCard').querySelector('.modal-actions') && ($('modalCard').querySelector('.modal-actions').innerHTML = '');
    showModal();
  }

  // ---- 目标体重设定 ----
  function openTargetModal() {
    var t = state.weightTarget;
    $('modalTitle').textContent = '目标体重设定';
    $('modalBody').innerHTML =
      '<label>目标体重(kg) *<input type="number" id="tg-target" min="0.1" step="0.1" value="' + (t.target || '') + '"/></label>' +
      '<label>起始体重(kg)<input type="number" id="tg-start" min="0" step="0.1" value="' + (t.startWeight || '') + '" placeholder="留空则取首条记录"/></label>' +
      '<label>目标达成日期<input type="date" id="tg-date" value="' + (t.targetDate || '') + '"/></label>' +
      '<div class="modal-actions"><button class="btn primary" id="tgSave">保存</button><button class="btn ghost" id="tgCancel">取消</button></div>';
    $('tgSave').onclick = function () {
      var tg = num($('tg-target').value);
      if (tg <= 0) { toast('请填写目标体重', 'err'); return; }
      state.weightTarget = { target: tg, startWeight: num($('tg-start').value), targetDate: $('tg-date').value };
      saveState(); closeModal(); renderWeight(); renderOverview();
      toast('目标已保存', 'ok');
    };
    $('tgCancel').onclick = closeModal;
    showModal();
  }

  // ---- CSV 导出 ----
  function exportWeightCsv() {
    var header = ['日期', '时间', '体重', '体脂率', '腰围', '臀围', '胸围', '大腿围', '手臂围', '备注'];
    var rows = weightSorted().map(function (w) {
      var ms = w.measurements || {};
      return [w.date, w.time || '', w.weight, w.bodyfat || '', ms.waist || '', ms.hip || '', ms.chest || '', ms.thigh || '', ms.arm || '', w.note || ''];
    });
    var csv = '﻿' + header.join(',') + '\n' + rows.map(function (r) {
      return r.map(function (c) { c = String(c); return /[",\n]/.test(c) ? '"' + c.replace(/"/g, '""') + '"' : c; }).join(',');
    }).join('\n');
    var blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    var a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = 'weight-' + TODAY + '.csv'; a.click(); URL.revokeObjectURL(a.href);
    toast('已导出 CSV', 'ok');
  }

  // ---- 旧数据迁移（无 time 字段的老记录） ----
  function migrateWeight() {
    var need = state.weight.some(function (w) { return w.time === undefined; });
    if (need) {
      state.weight = state.weight.map(function (w) {
        return { id: w.id || uid(), date: w.date, time: w.time || '08:00', weight: num(w.weight), bodyfat: num(w.bodyfat || 0), measurements: w.measurements || {}, note: w.note || '', photo: w.photo || '' };
      });
      saveState();
    }
  }

  /* ============ 模块5：理财管理（流水 / 账户 / 预算 / 报表） ============ */
  var financeTab = 'flow';
  var finFilter = { range: 'month', type: 'all', cat: 'all', acct: 'all' };
  var repFilter = { range: 'month', acct: 'all' };

  function setSegActive(seg, btn) {
    Array.prototype.forEach.call(seg.querySelectorAll('button'), function (x) { x.classList.remove('active'); });
    btn.classList.add('active');
  }
  function populateFinFilters() {
    var tops = getCats('expense').concat(getCats('income')).map(function (c) { return c.name; });
    if ($('finFilterType')) $('finFilterType').value = finFilter.type;
    if ($('finFilterCat')) { $('finFilterCat').innerHTML = '<option value="all">全部分类</option>' + tops.map(function (t) { return '<option value="' + esc(t) + '">' + esc(t) + '</option>'; }).join(''); $('finFilterCat').value = finFilter.cat; }
    if ($('finFilterAcct')) { $('finFilterAcct').innerHTML = '<option value="all">全部账户</option>' + acctOptions(finFilter.acct); $('finFilterAcct').value = finFilter.acct; }
  }

  function renderFinance() {
    renderFinCards();
    // 同步 Tab 显示
    document.querySelectorAll('[data-fin-tab]').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-fin-tab') === financeTab); });
    document.querySelectorAll('[data-fin-pane]').forEach(function (p) { p.classList.toggle('active', p.getAttribute('data-fin-pane') === financeTab); });
    if (financeTab === 'flow') renderFlow();
    else if (financeTab === 'accounts') renderAccounts();
    else if (financeTab === 'budget') renderBudgets();
    else if (financeTab === 'report') renderReport();
  }

  function renderFinCards() {
    var ym = TODAY.slice(0, 7), inc = 0, out = 0;
    state.finance.forEach(function (t) {
      if (monthKey(t.date) === ym) { if (t.txType === '收入') inc += num(t.amount); else if (t.txType === '支出') out += num(t.amount); }
    });
    var asset = 0, liability = 0;
    (state.accounts || []).forEach(function (a) {
      var bal = acctBalance(a);
      if (a.type === '信用卡') { if (bal < 0) liability += -bal; } else asset += bal;
    });
    var hide = state.finHide || {};
    var cells = [
      { k: '总资产', v: money(asset), c: 'asset', eye: true, key: 'asset' },
      { k: '本月收入', v: money(inc), c: 'income', eye: true, key: 'income' },
      { k: '本月支出', v: money(out), c: 'expense', eye: true, key: 'expense' },
      { k: '本月结余', v: money(inc - out), c: '', eye: true, key: 'balance' }
    ];
    $('finCards').innerHTML = cells.map(function (c) {
      var valHtml = '<div class="v ' + c.c + '">' + (c.eye && hide[c.key] ? '****' : c.v) + '</div>';
      var eyeBtn = c.eye ? ('<span class="eye-toggle" data-key="' + c.key + '" title="' + (hide[c.key] ? '显示金额' : '隐藏金额') + '">' + (hide[c.key] ? '🙈' : '👁️') + '</span>') : '';
      return '<div class="fin-card"><div class="k">' + c.k + eyeBtn + '</div>' + valHtml + '</div>';
    }).join('');
    // 绑定眼睛点击
    Array.prototype.forEach.call($('finCards').querySelectorAll('.eye-toggle'), function (el) {
      el.onclick = function () {
        var key = el.getAttribute('data-key');
        if (!state.finHide) state.finHide = {};
        state.finHide[key] = !state.finHide[key];
        saveState();
        renderFinCards();
      };
    });
  }

  /* ---- Tab 1：流水 ---- */
  function flowTxs() {
    var r = getRange(finFilter.range, $('finRangeStart').value, $('finRangeEnd').value);
    return state.finance.filter(function (t) {
      if (!inRange(t.date, r)) return false;
      if (finFilter.type !== 'all' && t.txType !== finFilter.type) return false;
      if (finFilter.cat !== 'all' && t.catTop !== finFilter.cat) return false;
      if (finFilter.acct !== 'all') {
        if (t.txType === '转账') { if (t.fromAccount !== finFilter.acct && t.toAccount !== finFilter.acct) return false; }
        else if (t.account !== finFilter.acct) return false;
      }
      return true;
    }).sort(function (a, b) { return a.date < b.date ? 1 : a.date > b.date ? -1 : 0; });
  }
  function renderFlow() {
    populateFinFilters();
    var list = flowTxs();
    var box = $('financeList');
    if (!list.length) { box.innerHTML = emptyState('💸', '还没有记账记录，点右下角“记一笔”'); return; }
    box.innerHTML = list.map(function (t) {
      var cls = t.txType === '收入' ? 'amount-in' : t.txType === '支出' ? 'amount-out' : 'amount-trans';
      var sign = t.txType === '收入' ? '+' : t.txType === '支出' ? '-' : '';
      var mid, sub;
      if (t.txType === '转账') { mid = '<span class="tag muted">转账</span>'; sub = acctName(t.fromAccount) + ' → ' + acctName(t.toAccount); }
      else {
        mid = '<span class="tag ' + (t.txType === '收入' ? 'green' : 'orange') + '">' + esc(t.catTop) + (t.catSub && t.catSub !== t.catTop ? '·' + esc(t.catSub) : '') + '</span>';
        sub = acctName(t.account) + (t.merchant ? ' · ' + esc(t.merchant) : '');
      }
      var extra = t.note ? ' · ' + esc(t.note) : '';
      return '<div class="item" data-id="' + t.id + '">' +
        '<div class="body"><div class="line1">' + mid + '<span class="' + cls + '">' + sign + money(t.amount) + '</span></div>' +
        '<div class="line2">' + esc(t.date) + ' · ' + sub + extra + '</div></div>' +
        '<div class="ops"><button class="icon-btn" data-act="edit" data-mod="tx" title="编辑">✏️</button>' +
        '<button class="icon-btn" data-act="del" data-mod="tx" title="删除">🗑️</button></div></div>';
    }).join('');
  }

  /* ---- Tab 2：账户 ---- */
  function renderAccounts() {
    var asset = 0, liability = 0;
    (state.accounts || []).forEach(function (a) {
      var bal = acctBalance(a);
      if (a.type === '信用卡') { if (bal < 0) liability += -bal; } else asset += bal;
    });
    $('finAcctSummary').innerHTML = '总资产 <b>' + money(asset) + '</b> · 总负债 <b>' + money(liability) + '</b> · 净资产 <b>' + money(asset - liability) + '</b>';
    var grid = $('finAcctGrid');
    if (!state.accounts.length) { grid.innerHTML = emptyState('📂', '还没有账户，先添加一个吧'); return; }
    grid.innerHTML = state.accounts.map(function (a) {
      var bal = acctBalance(a);
      var bcls = bal >= 0 ? 'pos' : 'neg';
      return '<div class="acct-card" data-id="' + a.id + '">' +
        '<div class="acct-ops"><button class="icon-btn" data-act="edit" data-mod="acct" title="编辑">✏️</button>' +
        '<button class="icon-btn" data-act="del" data-mod="acct" title="删除">🗑️</button></div>' +
        '<div class="acct-name">' + esc(a.name) + ' <span class="acct-type">' + esc(a.type) + '</span></div>' +
        '<div class="acct-bal ' + bcls + '">' + money(bal) + '</div>' +
        (a.note ? '<div class="acct-note">' + esc(a.note) + '</div>' : '') + '</div>';
    }).join('');
    Array.prototype.forEach.call(grid.querySelectorAll('.acct-card'), function (card) {
      card.onclick = function (e) {
        if (e.target.closest('[data-act]')) return;
        finFilter.acct = card.getAttribute('data-id');
        financeTab = 'flow'; renderFinance();
      };
    });
  }

  /* ---- Tab 3：预算 ---- */
  function budPeriod() { return $('budCycle').value === '年度' ? TODAY.slice(0, 4) : TODAY.slice(0, 7); }
  function budUsed(b) {
    var used = 0;
    state.finance.forEach(function (t) {
      if (t.txType === '支出' && t.catTop === b.catTop) {
        var ok = b.cycle === '月度' ? monthKey(t.date) === b.period : yearKey(t.date) === b.period;
        if (ok) used += num(t.amount);
      }
    });
    return used;
  }
  function renderBudgets() {
    if ($('budCycle')) var cyc = $('budCycle').value;
    var period = budPeriod();
    var list = state.budgets.filter(function (b) { return b.cycle === cyc && b.period === period; });
    var totalBud = 0, totalUsed = 0;
    list.forEach(function (b) { totalBud += num(b.amount); totalUsed += budUsed(b); });
    $('finBudSummary').innerHTML = '总预算 <b>' + money(totalBud) + '</b> · 总支出 <b>' + money(totalUsed) + '</b> · 剩余 <b>' + money(totalBud - totalUsed) + '</b>';
    var box = $('finBudList');
    if (!list.length) { box.innerHTML = emptyState('🎯', '还没有' + cyc + '预算，点“添加预算”'); return; }
    box.innerHTML = list.map(function (b) {
      var used = budUsed(b), amt = num(b.amount), pct = amt > 0 ? used / amt : 0;
      var fillCls = pct > 1 ? 'over' : pct > 0.9 ? 'warn' : 'ok';
      var left = amt - used;
      var leftTxt = left >= 0 ? ('剩余 ' + money(left)) : ('超支 ' + money(left) + ' ⚠️');
      return '<div class="bud-item" data-id="' + b.id + '">' +
        '<div class="bud-row"><span class="bud-cat">' + esc(b.catTop) + '</span>' +
        '<span class="bud-amount">已用 ' + money(used) + ' / 预算 ' + money(amt) + '</span></div>' +
        '<div class="bud-bar"><div class="bud-fill ' + fillCls + '" style="width:' + Math.min(100, pct * 100) + '%"></div></div>' +
        '<div class="bud-left ' + (left < 0 ? 'over' : '') + '">' + leftTxt + '</div>' +
        '<div class="bud-ops"><button class="icon-btn" data-act="edit" data-mod="bud" title="编辑">✏️</button>' +
        '<button class="icon-btn" data-act="del" data-mod="bud" title="删除">🗑️</button></div></div>';
    }).join('');
  }

  /* ---- Tab 4：报表 ---- */
  function svgLine(inc, out, labels) {
    var W = 520, H = 200, pl = 38, pr = 12, pt = 14, pb = 26;
    var max = 1;
    for (var i = 0; i < inc.length; i++) { max = Math.max(max, inc[i], out[i]); }
    max = max * 1.15;
    var n = labels.length;
    var x = function (i) { return n <= 1 ? (pl + (W - pl - pr) / 2) : pl + (W - pl - pr) * i / (n - 1); };
    var y = function (v) { return pt + (H - pt - pb) * (1 - v / max); };
    var grid = '';
    for (var g = 0; g <= 3; g++) { var gv = max * g / 3; var gy = y(gv); grid += '<line x1="' + pl + '" y1="' + gy + '" x2="' + (W - pr) + '" y2="' + gy + '" stroke="#ECE8E4" stroke-width="1"/><text x="' + (pl - 6) + '" y="' + (gy + 3) + '" font-size="9" fill="#8A8A8A" text-anchor="end">' + Math.round(gv) + '</text>'; }
    function path(arr) { return arr.map(function (v, i) { return (i === 0 ? 'M' : 'L') + x(i).toFixed(1) + ' ' + y(v).toFixed(1); }).join(' '); }
    var dotsInc = '', dotsOut = '';
    for (var k = 0; k < n; k++) {
      dotsInc += '<circle cx="' + x(k).toFixed(1) + '" cy="' + y(inc[k]).toFixed(1) + '" r="2.5" fill="#2D7D46"/>';
      dotsOut += '<circle cx="' + x(k).toFixed(1) + '" cy="' + y(out[k]).toFixed(1) + '" r="2.5" fill="#C0392B"/>';
    }
    var xl = '';
    for (var j = 0; j < n; j++) { if (n > 8 && j % 2 !== 0 && j !== n - 1) continue; xl += '<text x="' + x(j).toFixed(1) + '" y="' + (H - 8) + '" font-size="9" fill="#8A8A8A" text-anchor="middle">' + labels[j] + '</text>'; }
    return '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img"><defs></defs>' + grid +
      '<path d="' + path(out) + '" fill="none" stroke="#C0392B" stroke-width="2" stroke-linejoin="round"/>' +
      '<path d="' + path(inc) + '" fill="none" stroke="#2D7D46" stroke-width="2" stroke-linejoin="round"/>' +
      dotsOut + dotsInc + xl + '</svg>';
  }
  function svgDonut(items) {
    var total = items.reduce(function (s, i) { return s + i.value; }, 0);
    if (total <= 0) return '';
    var cx = 100, cy = 100, r = 70, sw = 26, C = 2 * Math.PI * r;
    var acc = 0, arcs = '';
    items.forEach(function (it) {
      var seg = it.value / total * C;
      arcs += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' + it.color + '" stroke-width="' + sw + '" stroke-dasharray="' + seg.toFixed(2) + ' ' + (C - seg).toFixed(2) + '" stroke-dashoffset="' + (-acc).toFixed(2) + '" transform="rotate(-90 ' + cx + ' ' + cy + ')"/>';
      acc += seg;
    });
    var legend = '<div class="rep-legend">' + items.map(function (it) {
      return '<span class="lg"><span class="dot" style="background:' + it.color + '"></span>' + esc(it.name) + ' ' + Math.round(it.value / total * 100) + '%</span>';
    }).join('') + '</div>';
    var svg = '<svg viewBox="0 0 200 200" role="img"><circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="#F1EFEC" stroke-width="' + sw + '"/><g>' + arcs + '</g>' +
      '<text x="' + cx + '" y="' + (cy - 4) + '" font-size="13" fill="#8A8A8A" text-anchor="middle">合计</text>' +
      '<text x="' + cx + '" y="' + (cy + 14) + '" font-size="14" font-weight="600" fill="#3D3D3D" text-anchor="middle">' + money(total) + '</text></svg>';
    return '<div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap"><div style="flex:0 0 160px;max-width:160px">' + svg + '</div><div style="flex:1;min-width:160px">' + legend + '</div></div>';
  }
  function svgBar(items) {
    if (!items.length) return '<div class="empty" style="padding:20px 0">暂无支出分类</div>';
    var max = items[0].value || 1;
    var rows = items.map(function (it) {
      var pct = Math.max(4, it.value / max * 100);
      return '<div style="margin-bottom:10px"><div style="display:flex;justify-content:space-between;font-size:12px;color:#8A8A8A;margin-bottom:4px"><span>' + esc(it.name) + '</span><span>' + money(it.value) + '</span></div>' +
        '<div style="height:8px;background:#EDE9E5;border-radius:4px;overflow:hidden"><div style="height:100%;width:' + pct.toFixed(1) + '%;background:' + it.color + ';border-radius:4px"></div></div></div>';
    }).join('');
    return rows;
  }
  function renderReport() {
    if ($('repFilterAcct')) { $('repFilterAcct').innerHTML = '<option value="all">全部账户</option>' + acctOptions(repFilter.acct); $('repFilterAcct').value = repFilter.acct; }
    var r = getRange(repFilter.range, $('repRangeStart').value, $('repRangeEnd').value);
    var txs = state.finance.filter(function (t) {
      if (!inRange(t.date, r)) return false;
      if (repFilter.acct !== 'all') {
        if (t.txType === '转账') { if (t.fromAccount !== repFilter.acct && t.toAccount !== repFilter.acct) return false; }
        else if (t.account !== repFilter.acct) return false;
      }
      return true;
    });
    // 收支趋势
    var days = Math.round((new Date(r.end) - new Date(r.start)) / 86400000) + 1;
    var byMonth = days > 31;
    var buckets = {}, labels = [];
    if (byMonth) {
      var cur = new Date(r.start); var end = new Date(r.end);
      while (cur <= end) { var mk = fmtDate(cur).slice(0, 7); if (!buckets[mk]) { buckets[mk] = { inc: 0, out: 0 }; labels.push(mk); } cur.setMonth(cur.getMonth() + 1); }
    } else {
      var cd = new Date(r.start);
      while (cd <= new Date(r.end)) { var dk = fmtDate(cd); buckets[dk] = { inc: 0, out: 0 }; labels.push(dk.slice(5)); cd.setDate(cd.getDate() + 1); }
    }
    var incA = [], outA = [];
    txs.forEach(function (t) {
      var key = byMonth ? monthKey(t.date) : t.date;
      if (!buckets[key]) buckets[key] = { inc: 0, out: 0 };
      if (t.txType === '收入') buckets[key].inc += num(t.amount);
      else if (t.txType === '支出') buckets[key].out += num(t.amount);
    });
    labels.forEach(function (lb) { var b = buckets[byMonth ? lb : Object.keys(buckets).find(function (x) { return x.slice(5) === lb; })] || { inc: 0, out: 0 }; incA.push(b.inc); outA.push(b.out); });
    var trend = svgLine(incA, outA, labels);

    // 支出分布 / 收入构成
    var expMap = {}, incMap = {};
    txs.forEach(function (t) {
      if (t.txType === '支出') expMap[t.catTop] = (expMap[t.catTop] || 0) + num(t.amount);
      else if (t.txType === '收入') incMap[t.catTop] = (incMap[t.catTop] || 0) + num(t.amount);
    });
    var expItems = Object.keys(expMap).map(function (k, i) { return { name: k, value: expMap[k], color: FIN_COLORS[i % FIN_COLORS.length] }; }).sort(function (a, b) { return b.value - a.value; });
    var incItems = Object.keys(incMap).map(function (k, i) { return { name: k, value: incMap[k], color: FIN_COLORS[i % FIN_COLORS.length] }; }).sort(function (a, b) { return b.value - a.value; });
    var expDonut = expItems.length ? svgDonut(expItems) : '<div class="empty" style="padding:20px 0">暂无支出数据</div>';
    var incDonut = incItems.length ? svgDonut(incItems) : '<div class="empty" style="padding:20px 0">暂无收入数据</div>';

    // 分类排行 Top5
    var top5 = expItems.slice(0, 5).map(function (it, i) { return { name: it.name, value: it.value, color: FIN_COLORS[i % FIN_COLORS.length] }; });

    $('finReport').innerHTML =
      '<div class="report-card chart"><div class="rep-title">收支趋势</div>' + trend + '</div>' +
      '<div class="report-card"><div class="rep-title">支出分布</div>' + expDonut + '</div>' +
      '<div class="report-card"><div class="rep-title">收入构成</div>' + incDonut + '</div>' +
      '<div class="report-card"><div class="rep-title">分类排行（支出 Top5）</div>' + svgBar(top5) + '</div>';
  }

  /* ---- 模态框 ---- */
  function showModal() { $('modalOverlay').hidden = false; }
  function closeModal() { $('modalOverlay').hidden = true; $('modalBody').innerHTML = ''; editing.tx = editing.acct = editing.bud = editing.book = editing.note = editing.exercise = null; }
  function acctOptions(sel, exclude) {
    return (state.accounts || []).map(function (a) {
      return '<option value="' + a.id + '"' + (a.id === sel ? ' selected' : '') + '>' + esc(a.name) + '</option>';
    }).join('');
  }
  function catTopOptions(kind, sel) {
    return getCats(kind).map(function (c) {
      return '<option value="' + esc(c.name) + '"' + (c.name === sel ? ' selected' : '') + '>' + esc(c.name) + '</option>';
    }).join('');
  }
  function catSubOptions(kind, top, sel) {
    var c = getCats(kind).find(function (x) { return x.name === top; });
    var subs = c ? c.children : [];
    if (!subs.length) return '<option value="' + esc(top) + '"' + (top === sel ? ' selected' : '') + '>' + esc(top) + '（无二级）</option>';
    return subs.map(function (s) { return '<option value="' + esc(s) + '"' + (s === sel ? ' selected' : '') + '>' + esc(s) + '</option>'; }).join('');
  }
  function renderTxDyn(type, rec) {
    var box = $('txDyn'); if (!box) return;
    if (type === '转账') {
      box.innerHTML = '<label>转出账户<select id="tx-from">' + acctOptions(rec ? rec.fromAccount : '') + '</select></label>' +
        '<label>转入账户<select id="tx-to">' + acctOptions(rec ? rec.toAccount : '') + '</select></label>';
    } else {
      var kind = type === '收入' ? 'income' : 'expense';
      var cats = getCats(kind);
      var defTop = cats[0] ? cats[0].name : '';
      var defSub = (cats[0] && cats[0].children.length) ? cats[0].children[0] : defTop;
      var selTop = rec ? rec.catTop : defTop;
      var selSub = rec ? rec.catSub : defSub;

      // 构建图标网格
      var groupsHtml = '';
      cats.forEach(function (cg) {
        var icons = CAT_ICONS[cg.name] || {};
        var itemsHtml = cg.children.map(function (sub) {
          var ico = icons[sub] || '📌';
          var isSel = (cg.name === selTop && sub === selSub) ? ' sel' : '';
          return '<div class="cat-item' + isSel + '" data-top="' + esc(cg.name) + '" data-sub="' + esc(sub) + '">' +
            '<span class="cat-icon">' + ico + '</span><span class="cat-label">' + esc(sub) + '</span></div>';
        }).join('');
        if (itemsHtml) groupsHtml += '<div class="cat-group-title">' + esc(cg.name) + '</div><div class="cat-grid">' + itemsHtml + '</div>';
      });

      box.innerHTML =
        '<input type="hidden" id="tx-top" value="' + esc(selTop) + '"/>' +
        '<input type="hidden" id="tx-sub" value="' + esc(selSub) + '"/>' +
        '<div class="cat-picker">' + groupsHtml + '</div>' +
        '<label style="margin-top:10px">账户<select id="tx-account">' + acctOptions(rec ? rec.account : '') + '</select></label>' +
        '<button class="link-btn" id="txAddCatBtn" type="button">＋ 新增分类</button>' +
        '<div id="txCatCustom" hidden><div class="grid-2">' +
        '<label>新一级分类<input id="txNewTop" placeholder="可选"/></label>' +
        '<label>新二级分类<input id="txNewSub" placeholder="可选"/></label></div>' +
        '<button class="btn primary sm" id="txCatSave" type="button" style="margin-top:8px">添加</button></div>';

      // 点击图标项
      Array.prototype.forEach.call(box.querySelectorAll('.cat-item'), function (item) {
        item.onclick = function () {
          box.querySelectorAll('.cat-item').forEach(function (x) { x.classList.remove('sel'); });
          item.classList.add('sel');
          $('tx-top').value = item.getAttribute('data-top');
          $('tx-sub').value = item.getAttribute('data-sub');
        };
      });
      // 滚动到已选项
      setTimeout(function () {
        var selEl = box.querySelector('.cat-item.sel');
        if (selEl) selEl.scrollIntoView({ block: 'center', behavior: 'auto' });
      }, 50);

      $('txAddCatBtn').onclick = function () { $('txCatCustom').hidden = !$('txCatCustom').hidden; };
      $('txCatSave').onclick = function () {
        var nt = $('txNewTop').value.trim(), ns = $('txNewSub').value.trim();
        if (!nt && !ns) { toast('请填写分类名称', 'err'); return; }
        if (ns && !nt && !$('tx-top').value) { toast('请先选择或填写一级分类', 'err'); return; }
        if (nt) state.finCats.push({ kind: kind, name: nt, parent: '' });
        if (ns) state.finCats.push({ kind: kind, name: ns, parent: nt || $('tx-top').value });
        saveState();
        // 刷新网格
        var newTop = nt || $('tx-top').value;
        $('tx-top').value = newTop;
        if (ns) { $('tx-sub').value = ns; }
        renderTxDyn(type, { catTop: newTop, catSub: ns || $('tx-sub').value, account: $('tx-account').value });
        $('txNewTop').value = ''; $('txNewSub').value = ''; $('txCatCustom').hidden = true;
        toast('分类已添加', 'ok');
      };
    }
  }
  function openTxModal(id) {
    editing.tx = id || null;
    var rec = id ? state.finance.find(function (t) { return t.id === id; }) : null;
    var type = rec ? rec.txType : '支出';
    $('modalTitle').textContent = rec ? '编辑记账' : '记一笔';
    $('modalBody').innerHTML =
      '<div class="tx-type" id="txType">' +
      ['支出', '收入', '转账'].map(function (v) { return '<label data-v="' + v + '"' + (v === type ? ' class="sel"' : '') + '><input type="radio" name="tx-type" value="' + v + '"' + (v === type ? ' checked' : '') + '/>' + v + '</label>'; }).join('') +
      '</div>' +
      '<label style="margin-top:12px">日期<input type="date" id="tx-date" value="' + (rec ? rec.date : TODAY) + '"/></label>' +
      '<label>金额(元) *<input type="number" id="tx-amount" min="0.01" step="0.01" placeholder="金额" value="' + (rec ? rec.amount : '') + '"/></label>' +
      '<div id="txDyn"></div>' +
      '<label>商家 / 对方<input type="text" id="tx-merchant" placeholder="可选" value="' + (rec ? esc(rec.merchant || '') : '') + '"/></label>' +
      '<label>备注<input type="text" id="tx-note" placeholder="可选" value="' + (rec ? esc(rec.note || '') : '') + '"/></label>' +
      '<div class="modal-actions"><button class="btn primary" id="txSave">保存</button><button class="btn ghost" id="txCancel">取消</button></div>';
    Array.prototype.forEach.call($('txType').querySelectorAll('label'), function (l) {
      l.onclick = function () {
        Array.prototype.forEach.call($('txType').querySelectorAll('label'), function (x) { x.classList.remove('sel'); x.querySelector('input').checked = false; });
        l.classList.add('sel'); l.querySelector('input').checked = true;
        renderTxDyn(l.getAttribute('data-v'), null);
      };
    });
    renderTxDyn(type, rec);
    $('txSave').onclick = saveTx;
    $('txCancel').onclick = closeModal;
    showModal();
  }
  function saveTx() {
    var date = $('tx-date').value || TODAY;
    var type = radioVal('tx-type');
    var amt = num($('tx-amount').value);
    if (amt <= 0) { toast('金额须大于0', 'err'); return; }
    var obj = { id: editing.tx || uid(), date: date, txType: type, amount: amt, merchant: $('tx-merchant').value.trim(), note: $('tx-note').value.trim() };
    if (type === '转账') {
      var from = $('tx-from').value, to = $('tx-to').value;
      if (!from || !to) { toast('请选择转出与转入账户', 'err'); return; }
      if (from === to) { toast('转出与转入账户不能相同', 'err'); return; }
      obj.fromAccount = from; obj.toAccount = to;
    } else {
      var top = $('tx-top').value, sub = $('tx-sub').value, ac = $('tx-account').value;
      if (!top || !sub) { toast('请选择分类', 'err'); return; }
      if (!ac) { toast('请选择账户', 'err'); return; }
      obj.catTop = top; obj.catSub = sub; obj.account = ac;
    }
    if (editing.tx) { var i = state.finance.findIndex(function (x) { return x.id === editing.tx; }); if (i >= 0) state.finance[i] = obj; }
    else state.finance.push(obj);
    saveState(); closeModal(); renderFinance();
    toast('已保存', 'ok');
  }
  function deleteTx(id) {
    if (!confirmDel()) return;
    state.finance = state.finance.filter(function (x) { return x.id !== id; });
    saveState(); renderFinance();
  }
  function openAcctModal(id) {
    editing.acct = id || null;
    var rec = id ? state.accounts.find(function (a) { return a.id === id; }) : null;
    $('modalTitle').textContent = rec ? '编辑账户' : '添加账户';
    var types = ['银行卡', '支付宝', '微信支付', '现金', '信用卡', '其他'];
    $('modalBody').innerHTML =
      '<label>账户名称 *<input type="text" id="ac-name" placeholder="如 招商银行卡" value="' + (rec ? esc(rec.name) : '') + '"/></label>' +
      '<label>账户类型<select id="ac-type">' + types.map(function (t) { return '<option' + (rec && rec.type === t ? ' selected' : '') + '>' + t + '</option>'; }).join('') + '</select></label>' +
      '<label>初始余额(元)<input type="number" id="ac-init" step="0.01" value="' + (rec ? rec.init : 0) + '"/></label>' +
      '<label>账户备注<input type="text" id="ac-note" placeholder="如 工资卡" value="' + (rec ? esc(rec.note || '') : '') + '"/></label>' +
      '<div class="modal-actions"><button class="btn primary" id="acSave">保存</button><button class="btn ghost" id="acCancel">取消</button></div>';
    $('acSave').onclick = saveAcct; $('acCancel').onclick = closeModal;
    showModal();
  }
  function saveAcct() {
    var name = $('ac-name').value.trim();
    if (!name) { toast('请填写账户名称', 'err'); return; }
    var obj = { id: editing.acct || uid(), name: name, type: $('ac-type').value, init: num($('ac-init').value), note: $('ac-note').value.trim() };
    if (editing.acct) { var i = state.accounts.findIndex(function (x) { return x.id === editing.acct; }); if (i >= 0) state.accounts[i] = obj; }
    else state.accounts.push(obj);
    saveState(); closeModal(); renderFinance();
    toast('已保存', 'ok');
  }
  function deleteAcct(id) {
    var cnt = state.finance.filter(function (t) {
      if (t.txType === '转账') return t.fromAccount === id || t.toAccount === id;
      return t.account === id;
    }).length;
    var msg = cnt > 0 ? ('该账户有 ' + cnt + ' 条流水记录，删除账户不会删除流水，但流水中的账户信息将显示为“已删除账户”，是否继续？') : '确定要删除这个账户吗？';
    if (!window.confirm(msg)) return;
    state.finance.forEach(function (t) {
      if (t.txType === '转账') { if (t.fromAccount === id) t.fromAccount = 'deleted'; if (t.toAccount === id) t.toAccount = 'deleted'; }
      else if (t.account === id) t.account = 'deleted';
    });
    state.accounts = state.accounts.filter(function (x) { return x.id !== id; });
    saveState(); renderFinance();
  }
  function openBudModal(id) {
    editing.bud = id || null;
    var rec = id ? state.budgets.find(function (b) { return b.id === id; }) : null;
    $('modalTitle').textContent = rec ? '编辑预算' : '添加预算';
    var cyc = rec ? rec.cycle : ($('budCycle') ? $('budCycle').value : '月度');
    var period = rec ? rec.period : budPeriod();
    var tops = getCats('expense').map(function (c) { return '<option' + (rec && rec.catTop === c.name ? ' selected' : '') + '>' + esc(c.name) + '</option>'; }).join('');
    $('modalBody').innerHTML =
      '<label>预算周期<select id="bd-cycle"' + (rec ? ' disabled' : '') + '>' +
      '<option value="月度"' + (cyc === '月度' ? ' selected' : '') + '>月度</option><option value="年度"' + (cyc === '年度' ? ' selected' : '') + '>年度</option></select></label>' +
      '<label>预算' + (cyc === '月度' ? '月份' : '年份') + '<input type="text" id="bd-period" value="' + period + '" disabled/></label>' +
      '<label>预算分类<select id="bd-cat"' + (rec ? ' disabled' : '') + '>' + tops + '</select></label>' +
      '<label>预算金额(元) *<input type="number" id="bd-amount" min="0.01" step="0.01" value="' + (rec ? rec.amount : '') + '"/></label>' +
      '<div class="modal-actions"><button class="btn primary" id="bdSave">保存</button><button class="btn ghost" id="bdCancel">取消</button></div>';
    $('bdSave').onclick = saveBud; $('bdCancel').onclick = closeModal;
    showModal();
  }
  function saveBud() {
    var cyc = $('bd-cycle').disabled ? ($('bd-cycle').value) : $('bd-cycle').value;
    var period = $('bd-period').value;
    var catTop = $('bd-cat').value;
    var amount = num($('bd-amount').value);
    if (amount <= 0) { toast('预算金额须大于0', 'err'); return; }
    if (!editing.bud) {
      var dup = state.budgets.some(function (b) { return b.cycle === cyc && b.period === period && b.catTop === catTop; });
      if (dup) { toast('该分类同周期已存在预算', 'err'); return; }
    }
    var obj = { id: editing.bud || uid(), cycle: cyc, period: period, catTop: catTop, amount: amount };
    if (editing.bud) { var i = state.budgets.findIndex(function (x) { return x.id === editing.bud; }); if (i >= 0) state.budgets[i] = obj; }
    else state.budgets.push(obj);
    saveState(); closeModal(); renderFinance();
    toast('已保存', 'ok');
  }
  function deleteBud(id) {
    if (!confirmDel()) return;
    state.budgets = state.budgets.filter(function (x) { return x.id !== id; });
    saveState(); renderFinance();
  }


  /* ============ 模块6：今日计划 ============ */
  var PLAN_ORDER = { '高': 0, '中': 1, '低': 2 };
  function renderPlan() {
    var showAll = $('pShowHistory').checked;
    var list = state.plan.filter(function (p) { return showAll || p.date === TODAY; });
    list.sort(function (a, b) {
      if (a.date !== b.date) return a.date < b.date ? 1 : -1;
      return PLAN_ORDER[a.priority] - PLAN_ORDER[b.priority];
    });
    var box = $('planList');
    if (!list.length) { box.innerHTML = emptyState('📝', '今天还没有计划，写一个吧'); return; }
    box.innerHTML = list.map(function (p) {
      var sCls = p.status === '已完成' ? 's-done' : p.status === '进行中' ? 's-doing' : '';
      var sym = p.status === '已完成' ? '✓' : p.status === '进行中' ? '…' : '';
      var head = '<span>' + (p.time ? esc(p.time) + ' ' : '') + esc(p.content) + '</span>' +
        '<span class="prio-tag">' + esc(p.priority) + '</span>' +
        (p.date !== TODAY ? '<span class="tag muted">' + esc(p.date) + '</span>' : '') +
        '<span class="tag ' + (p.status === '已完成' ? 'green' : p.status === '进行中' ? '' : 'muted') + '">' + esc(p.status) + '</span>';
      return '<div class="item ' + (p.status === '已完成' ? 'done-strike' : '') + '" data-id="' + p.id + '">' +
        '<button class="cycle-btn ' + sCls + '" data-act="cycle" data-mod="plan">' + sym + '</button>' +
        '<div class="body"><div class="line1">' + head + '</div></div>' +
        '<div class="ops"><button class="icon-btn" data-act="edit" data-mod="plan" title="编辑">✏️</button>' +
        '<button class="icon-btn" data-act="del" data-mod="plan" title="删除">🗑️</button></div></div>';
    }).join('');
  }
  function cyclePlan(id) {
    var p = state.plan.find(function (x) { return x.id === id; });
    if (!p) return;
    p.status = p.status === '未开始' ? '进行中' : p.status === '进行中' ? '已完成' : '未开始';
    saveState(); renderPlan();
  }
  function submitPlan() {
    var content = $('p-content').value.trim();
    if (!content) { toast('请填写事项内容', 'err'); return; }
    var rec = { id: uid(), date: TODAY, time: $('p-time').value.trim(), content: content, priority: $('p-priority').value, status: '未开始' };
    if (editing.plan) {
      var i = state.plan.findIndex(function (x) { return x.id === editing.plan; });
      if (i >= 0) state.plan[i] = Object.assign(state.plan[i], rec, { id: editing.plan });
      cancelEdit('plan');
    } else { state.plan.push(rec); flashOk($('p-submit')); }
    saveState(); clearForm('plan'); renderPlan();
  }

  /* ============ 模块7：待办计划 ============ */
  function renderTodo() {
    var showArch = $('tShowArchived').checked;
    var list = state.todo.filter(function (t) { return showArch || !t.isArchived; });
    list.sort(function (a, b) { return a.dueDate < b.dueDate ? -1 : a.dueDate > b.dueDate ? 1 : 0; });
    var box = $('todoList');
    if (!list.length) { box.innerHTML = emptyState('💼', '还没有待办计划'); renderTodoReminder(); return; }
    box.innerHTML = list.map(function (t) {
      var overdue = t.status === '已延期';
      var stCls = overdue ? 'red' : t.status === '已完成' ? 'green' : t.status === '进行中' ? '' : 'muted';
      var head = '<span' + (overdue ? ' style="color:var(--overdue)"' : '') + '>' + esc(t.content) + '</span>' +
        '<span class="prio-tag ' + esc(t.priority) + '">' + esc(t.priority) + '</span>' +
        (t.project ? '<span class="tag muted">' + esc(t.project) + '</span>' : '') +
        (t.isArchived ? '<span class="tag muted">已归档</span>' : '');
      var line2 = '截止 ' + esc(t.dueDate) + (overdue ? ' · 已逾期' : '');
      var sel = '<select class="status-select" data-act="status" data-mod="todo" data-id="' + t.id + '">' +
        ['待办', '进行中', '已完成', '已延期'].map(function (s) {
          return '<option' + (s === t.status ? ' selected' : '') + '>' + s + '</option>';
        }).join('') + '</select>';
      return '<div class="item" data-id="' + t.id + '">' +
        '<div class="body"><div class="line1">' + head + '</div><div class="line2">' + line2 + '</div></div>' +
        '<div class="ops">' + sel +
        '<button class="icon-btn" data-act="edit" data-mod="todo" title="编辑">✏️</button>' +
        '<button class="icon-btn" data-act="del" data-mod="todo" title="删除">🗑️</button></div></div>';
    }).join('');
    renderTodoReminder();
  }
  function setTodoStatus(id, status) {
    var t = state.todo.find(function (x) { return x.id === id; });
    if (!t) return;
    t.status = status;
    if (status === '已完成') t.completeDate = TODAY; else t.completeDate = '';
    saveState(); renderTodo();
  }
  function submitTodo() {
    var due = $('t-due').value;
    var content = $('t-content').value.trim();
    if (!due) { toast('请选择截止日期', 'err'); return; }
    if (!content) { toast('请填写事项内容', 'err'); return; }
    var status = $('t-status').value;
    var rec = {
      id: uid(), dueDate: due, content: content, project: $('t-project').value.trim(),
      priority: $('t-priority').value, status: status, isArchived: false,
      completeDate: status === '已完成' ? TODAY : ''
    };
    if (editing.todo) {
      var i = state.todo.findIndex(function (x) { return x.id === editing.todo; });
      if (i >= 0) state.todo[i] = Object.assign(state.todo[i], rec, { id: editing.todo });
      cancelEdit('todo');
    } else { state.todo.push(rec); flashOk($('t-submit')); }
    saveState(); clearForm('todo'); renderTodo();
  }

  /* ============ 待办提醒横幅 + 系统通知 ============ */
  var notifiedTodoIds = {};   // 本次会话已通知过的待办 id（避免重复弹窗）

  // 计算逾期 / 今天到期 的活跃待办（未完成且未归档）
  function todoDueItems() {
    var overdue = [], today = [];
    (state.todo || []).forEach(function (t) {
      if (t.isArchived || t.status === '已完成') return;
      if (!t.dueDate) return;
      if (t.dueDate < TODAY) overdue.push(t);
      else if (t.dueDate === TODAY) today.push(t);
    });
    return { overdue: overdue, today: today };
  }

  function renderTodoReminder() {
    var box = $('todoReminder'); if (!box) return;
    var d = todoDueItems();
    if (!d.overdue.length && !d.today.length) { box.hidden = true; box.innerHTML = ''; return; }
    function itemHtml(t, cls) {
      return '<div class="rem-item ' + cls + '"><span class="dot"></span>' +
        '<span class="rem-content">' + esc(t.content) + (t.project ? '（' + esc(t.project) + '）' : '') + '</span>' +
        '<span class="rem-date">' + esc(t.dueDate) + '</span></div>';
    }
    var perm = ('Notification' in window) ? Notification.permission : 'unsupported';
    var hint = '';
    var btn = '';
    if (perm === 'default') {
      btn = '<button class="rem-btn primary" id="remEnableBtn">🔔 开启到期提醒</button>';
      hint = '<span class="rem-hint">开启后，网页开着时会弹出系统通知</span>';
    } else if (perm === 'denied') {
      hint = '<span class="rem-hint">⚠️ 系统通知已被浏览器拦截，可在地址栏左侧重新允许</span>';
    }
    box.innerHTML =
      '<div class="rem-head"><span class="rem-ico">⏰</span>' +
      '<span>待办提醒：' + (d.overdue.length ? d.overdue.length + ' 项已逾期' : '') +
      (d.overdue.length && d.today.length ? '，' : '') +
      (d.today.length ? d.today.length + ' 项今天到期' : '') + '</span></div>' +
      '<div class="rem-list">' +
      d.overdue.map(function (t) { return itemHtml(t, 'overdue'); }).join('') +
      d.today.map(function (t) { return itemHtml(t, 'today'); }).join('') +
      '</div>' +
      (btn || hint ? '<div class="rem-actions">' + btn + hint + '</div>' : '');
    var eb = $('remEnableBtn');
    if (eb) eb.onclick = function () { requestNotifyPermission(); };
  }

  function requestNotifyPermission() {
    if (!('Notification' in window)) { toast('当前浏览器不支持系统通知', 'err'); return; }
    if (Notification.permission === 'granted') { toast('已开启，网页开着时会提醒', 'ok'); checkDeadlineNotifications(); return; }
    if (Notification.permission === 'denied') { toast('通知已被拒绝，请在浏览器设置中允许', 'err'); return; }
    Notification.requestPermission().then(function (p) {
      if (p === 'granted') { toast('已开启到期提醒', 'ok'); checkDeadlineNotifications(); }
      else toast('未授权，仅显示应用内横幅', 'ok');
      renderTodoReminder();
    });
  }

  function fireTodoNotification(t, kind) {
    try {
      var n = new Notification('⏰ 待办' + (kind === 'overdue' ? '已逾期' : '今天到期'), {
        body: t.content + (t.project ? '（' + t.project + '）' : '') + '\n截止：' + t.dueDate,
        tag: 'todo-' + t.id
      });
      n.onclick = function () { window.focus(); n.close(); };
    } catch (e) { /* 某些浏览器构造需带选项包一层 */ }
  }

  function checkDeadlineNotifications() {
    if (!('Notification' in window) || Notification.permission !== 'granted') return;
    var d = todoDueItems();
    d.overdue.concat(d.today).forEach(function (t) {
      if (!notifiedTodoIds[t.id]) { notifiedTodoIds[t.id] = 1; fireTodoNotification(t, t.dueDate < TODAY ? 'overdue' : 'today'); }
    });
  }

  // 初始化：加载时检查 + 每 60 秒轮询（网页需保持打开）
  function setupDeadlineNotifications() {
    checkDeadlineNotifications();
    if (window.__todoNotifyTimer) clearInterval(window.__todoNotifyTimer);
    window.__todoNotifyTimer = setInterval(checkDeadlineNotifications, 60000);
  }

  /* ============ 模块8：生活清单（清单 / 事项 / 视图 / 模板 / 统计） ============ */
  var LIFE_ICONS = ['📌', '🛒', '🎬', '🎯', '🧾', '📚', '🏠', '💡', '🍎', '✈️', '💊', '🐱', '🎁', '📝', '🏃', '🎵', '👗', '🔧', '💄', '🌿'];
  var LIFE_COLORS = ['#D4B8A8', '#B7C4B1', '#A7B8C9', '#E0C8A0', '#C9A9B0', '#9FB8B0', '#D8BFA8', '#B0A9C4', '#C2B89C', '#A9C0C4', '#CDB6C9', '#E6B8A0', '#9FB0C4', '#C4B9A0'];
  var lifeView = 'all';       // all | today | important | done
  var lifeSelList = null;     // 当前打开的清单 id

  function lifeListsSorted() { return (state.lifeLists || []).slice().sort(function (a, b) { return (a.order || 0) - (b.order || 0); }); }
  function lifeItemsOf(listId) { return (state.lifeItems || []).filter(function (i) { return i.listId === listId; }); }
  function lifeProgress(listId) {
    var items = lifeItemsOf(listId); var total = items.length;
    var done = items.filter(function (i) { return i.done; }).length;
    return { total: total, done: done, pct: total ? Math.round(done / total * 100) : 0 };
  }
  function listNameOf(id) { var l = (state.lifeLists || []).find(function (x) { return x.id === id; }); return l ? l.name : ''; }

  function renderLife() {
    renderLifeSummary();
    var main = $('lifeMain');
    if (lifeSelList) { main.innerHTML = renderLifeDetail(); bindLifeDetail(); return; }
    if (lifeView === 'all') main.innerHTML = renderLifeLists();
    else if (lifeView === 'today') main.innerHTML = renderLifeAgg('today');
    else if (lifeView === 'important') main.innerHTML = renderLifeAgg('important');
    else if (lifeView === 'done') main.innerHTML = renderLifeAgg('done');
  }

  function renderLifeSummary() {
    var lists = state.lifeLists || [];
    var items = state.lifeItems || [];
    var total = items.length;
    var done = items.filter(function (i) { return i.done; }).length;
    var due = items.filter(function (i) { return !i.done && i.dueDate === TODAY; }).length;
    var imp = items.filter(function (i) { return i.priority === 'important' && !i.done; }).length;
    var cells = [
      { k: '清单', v: lists.length + ' 个' },
      { k: '事项', v: total + ' 项' },
      { k: '已完成', v: done + ' 项' },
      { k: '今日到期', v: due + ' 件' },
      { k: '重要', v: imp + ' 件' }
    ];
    $('lifeSummary').innerHTML = '<div class="life-stats">' + cells.map(function (c) {
      return '<div class="life-stat"><div class="k">' + c.k + '</div><div class="v">' + esc(c.v) + '</div></div>';
    }).join('') + '</div>';
  }

  function setLifeViewActive(btn) {
    var seg = $('lifeViews');
    if (seg) Array.prototype.forEach.call(seg.querySelectorAll('[data-act="life-view"]'), function (b) { b.classList.toggle('active', b === btn); });
  }

  function renderLifeLists() {
    var lists = lifeListsSorted();
    if (!lists.length) return emptyState('🎀', '还没有清单，点右下角 + 新建第一个清单吧');
    var groups = {};
    lists.forEach(function (l) { var g = l.group || ''; (groups[g] = groups[g] || []).push(l); });
    var keys = (state.lifeGroups || []).slice();
    Object.keys(groups).forEach(function (g) { if (keys.indexOf(g) < 0) keys.push(g); });
    var html = '';
    keys.forEach(function (g) {
      if (g) html += '<div class="life-group-title">📂 ' + esc(g) + '</div>';
      html += '<div class="life-list-grid">';
      groups[g].forEach(function (l) {
        var pr = lifeProgress(l.id);
        var full = pr.total > 0 && pr.done === pr.total;
        var color = l.color || '#D4B8A8';
        html += '<div class="life-list-card" data-act="life-open" data-id="' + l.id + '" style="--lc:' + esc(color) + '">' +
          '<div class="life-list-bar"></div>' +
          '<div class="life-list-body">' +
            '<div class="life-list-row1">' +
              '<span class="life-list-icon">' + esc(l.icon || '📌') + '</span>' +
              '<span class="life-list-name">' + esc(l.name) + '</span>' +
              (full ? '<span class="life-list-check">✅</span>' : '') +
              '<span class="life-list-ops">' +
                '<button class="icon-btn" data-act="life-edit-list" data-id="' + l.id + '" title="编辑清单">✏️</button>' +
                '<button class="icon-btn" data-act="life-del-list" data-id="' + l.id + '" title="删除清单">🗑️</button>' +
              '</span>' +
            '</div>' +
            '<div class="life-progress"><div class="life-progress-fill' + (full ? ' full' : '') + '" style="width:' + pr.pct + '%"></div></div>' +
            '<div class="life-list-count">已完成 ' + pr.done + ' / ' + pr.total + '</div>' +
          '</div>' +
        '</div>';
      });
      html += '</div>';
    });
    html += renderLifeTemplates();
    return html;
  }

  function renderLifeTemplates() {
    var tps = state.lifeTemplates || [];
    var html = '<div class="life-tmpl-section"><div class="life-sec-title">📋 我的模板</div>';
    if (!tps.length) {
      html += '<div class="muted-tip">暂无模板，在清单详情页点「💾 保存为模板」可复用常用清单</div>';
    } else {
      html += '<div class="life-tmpl-grid">';
      tps.forEach(function (t) {
        html += '<div class="life-tmpl-card">' +
          '<div class="life-tmpl-icon">' + esc(t.icon || '📋') + '</div>' +
          '<div class="life-tmpl-name">' + esc(t.name) + '</div>' +
          '<div class="life-tmpl-ops">' +
            '<button class="btn ghost sm" data-act="life-use-tmpl" data-id="' + t.id + '">使用</button>' +
            '<button class="icon-btn" data-act="life-rename-tmpl" data-id="' + t.id + '" title="重命名">✏️</button>' +
            '<button class="icon-btn" data-act="life-del-tmpl" data-id="' + t.id + '" title="删除">🗑️</button>' +
          '</div>' +
        '</div>';
      });
      html += '</div>';
    }
    html += '</div>';
    return html;
  }

  function lifeItemHTML(i) {
    var sub = i.subtasks || [];
    var sd = sub.filter(function (s) { return s.done; }).length;
    var line2 = [];
    if (i.dueDate) line2.push('<span class="tag">📅 ' + esc(i.dueDate) + '</span>');
    if (sub.length) line2.push('<span class="tag muted">子任务 ' + sd + '/' + sub.length + '</span>');
    if (i.note) line2.push('<span class="muted-tip">📝 ' + esc(i.note) + '</span>');
    return '<div class="life-item' + (i.done ? ' done' : '') + '" data-id="' + i.id + '" draggable="true">' +
      '<button class="check-btn' + (i.done ? ' on' : '') + '" data-act="check" data-mod="life" title="完成"></button>' +
      (i.priority === 'important' ? '<span class="life-star">⭐️</span>' : '') +
      '<div class="body"><div class="line1"><span>' + esc(i.content) + '</span></div><div class="line2">' + line2.join(' ') + '</div></div>' +
      '<div class="ops"><button class="icon-btn" data-act="edit" data-mod="life" title="编辑">✏️</button>' +
      '<button class="icon-btn" data-act="del" data-mod="life" title="删除">🗑️</button></div>' +
    '</div>';
  }

  function renderLifeDetail() {
    var list = (state.lifeLists || []).find(function (l) { return l.id === lifeSelList; });
    if (!list) { lifeSelList = null; return renderLifeLists(); }
    var items = lifeItemsOf(list.id);
    var pr = lifeProgress(list.id);
    var full = pr.total > 0 && pr.done === pr.total;
    var color = list.color || '#D4B8A8';
    var html = '';
    html += '<div class="card life-detail-head" style="--lc:' + esc(color) + '">' +
      '<div class="life-detail-top">' +
        '<button class="icon-btn" data-act="life-back" title="返回">←</button>' +
        '<span class="life-list-icon">' + esc(list.icon || '📌') + '</span>' +
        '<span class="life-detail-name">' + esc(list.name) + '</span>' +
        (full ? '<span class="life-list-check">✅</span>' : '') +
        '<span class="life-detail-ops">' +
          '<button class="btn ghost sm" data-act="life-save-tmpl" data-id="' + list.id + '">💾 保存为模板</button>' +
          '<button class="icon-btn" data-act="life-edit-list" data-id="' + list.id + '" title="编辑清单">✏️</button>' +
        '</span>' +
      '</div>' +
      '<div class="life-progress"><div class="life-progress-fill' + (full ? ' full' : '') + '" style="width:' + pr.pct + '%"></div></div>' +
      '<div class="life-list-count">已完成 ' + pr.done + ' / ' + pr.total + '</div>' +
    '</div>';
    if (!items.length) {
      html += emptyState('📭', '这个清单还是空的，添加第一件事项吧');
    } else {
      var undone = items.filter(function (i) { return !i.done; }).sort(function (a, b) {
        // 手动拖拽顺序为主排序；截止日/优先级已在事项上以标签展示，不在列表内强制重排（否则拖拽排序无效）
        if ((a.order || 0) !== (b.order || 0)) return (a.order || 0) - (b.order || 0);
        var da = a.dueDate || '9999', db = b.dueDate || '9999';
        if (da !== db) return da < db ? -1 : 1;
        return (a.priority === 'important') === (b.priority === 'important') ? 0 : (a.priority === 'important' ? -1 : 1);
      });
      var doneItems = items.filter(function (i) { return i.done; }).sort(function (a, b) { return (b.completeDate || '') < (a.completeDate || '') ? -1 : 1; });
      html += '<div class="life-items" id="lifeItems">';
      undone.concat(doneItems).forEach(function (i) { html += lifeItemHTML(i); });
      html += '</div>';
    }
    html += '<div class="life-quick-add">' +
      '<input type="text" id="lifeQuickInput" placeholder="添加事项，回车保存…" />' +
      '<button class="btn primary" data-act="life-add-item" data-id="' + list.id + '">添加</button>' +
    '</div>';
    return html;
  }

  function renderLifeAgg(kind) {
    var items = state.lifeItems || [];
    var filtered = [], title = '', icon = '📋';
    if (kind === 'today') {
      filtered = items.filter(function (i) { return !i.done && i.dueDate === TODAY; });
      title = '今天有 ' + filtered.length + ' 件事项待处理'; icon = '📅';
    } else if (kind === 'important') {
      filtered = items.filter(function (i) { return i.priority === 'important' && !i.done; });
      title = '⭐️ 重要事项 ' + filtered.length + ' 件'; icon = '⭐️';
    } else if (kind === 'done') {
      filtered = items.filter(function (i) { return i.done; }).sort(function (a, b) { return (b.completeDate || '') < (a.completeDate || '') ? -1 : 1; });
      title = '✅ 已完成 ' + filtered.length + ' 件（点击可恢复）'; icon = '✅';
    }
    if (!filtered.length) return '<div class="card">' + emptyState(icon, '这里暂时没有事项') + '</div>';
    var html = '<div class="card life-agg-head">' + esc(title) + '</div><div class="life-items">';
    filtered.forEach(function (i) {
      var sub = i.subtasks || []; var sd = sub.filter(function (s) { return s.done; }).length;
      var line2 = ['<span class="tag muted">📂 ' + esc(listNameOf(i.listId)) + '</span>'];
      if (i.dueDate) line2.push('<span class="tag">📅 ' + esc(i.dueDate) + '</span>');
      if (sub.length) line2.push('<span class="tag muted">子任务 ' + sd + '/' + sub.length + '</span>');
      html += '<div class="life-item' + (i.done ? ' done' : '') + '" data-id="' + i.id + '" draggable="true">' +
        '<button class="check-btn' + (i.done ? ' on' : '') + '" data-act="check" data-mod="life" title="切换完成"></button>' +
        (i.priority === 'important' ? '<span class="life-star">⭐️</span>' : '') +
        '<div class="body"><div class="line1"><span>' + esc(i.content) + '</span></div><div class="line2">' + line2.join(' ') + '</div></div>' +
        '<div class="ops"><button class="icon-btn" data-act="edit" data-mod="life" title="编辑">✏️</button>' +
        '<button class="icon-btn" data-act="del" data-mod="life" title="删除">🗑️</button></div>' +
      '</div>';
    });
    html += '</div>';
    return html;
  }

  function toggleLifeItem(id) {
    var i = (state.lifeItems || []).find(function (x) { return x.id === id; });
    if (!i) return;
    var before = lifeProgress(i.listId);
    i.done = !i.done;
    i.completeDate = i.done ? TODAY : '';
    saveState(); renderLife(); renderOverview();
    var after = lifeProgress(i.listId);
    if (i.done && after.total > 0 && after.done === after.total && before.done !== after.done) {
      toast('🎉 清单「' + listNameOf(i.listId) + '」全部完成！', 'ok');
    }
  }
  function deleteLifeItem(id) {
    if (!confirmDel('确定删除这件事项吗？')) return;
    state.lifeItems = (state.lifeItems || []).filter(function (x) { return x.id !== id; });
    saveState(); renderLife(); renderOverview();
  }
  function deleteLifeList(id) {
    var l = (state.lifeLists || []).find(function (x) { return x.id === id; });
    if (!l) return;
    if (!confirmDel('删除清单「' + l.name + '」将同时删除其中的 ' + lifeItemsOf(id).length + ' 件事项，确定吗？')) return;
    state.lifeLists = (state.lifeLists || []).filter(function (x) { return x.id !== id; });
    state.lifeItems = (state.lifeItems || []).filter(function (x) { return x.listId !== id; });
    if (lifeSelList === id) lifeSelList = null;
    saveState(); renderLife(); renderOverview();
  }
  function moveLifeItem(id, targetId) {
    if (id === targetId) return;
    var items = state.lifeItems || [];
    var it = items.find(function (x) { return x.id === id; });
    if (!it) return;
    var others = items.filter(function (x) { return x.listId === it.listId && x.id !== id; }).sort(function (a, b) { return (a.order || 0) - (b.order || 0); });
    var idx = others.findIndex(function (x) { return x.id === targetId; });
    if (idx < 0) others.push(it); else others.splice(idx, 0, it);
    others.forEach(function (x, k) { x.order = k + 1; });
    saveState(); renderLife();
  }
  function lifeQuickAdd() {
    var input = $('lifeQuickInput');
    if (!input) return;
    var v = input.value.trim();
    if (!v) { toast('请输入事项内容', 'err'); return; }
    var lid = lifeSelList;
    var maxOrder = (state.lifeItems || []).filter(function (i) { return i.listId === lid; }).reduce(function (m, i) { return Math.max(m, i.order || 0); }, 0);
    state.lifeItems = (state.lifeItems || []).concat([{ id: uid(), listId: lid, content: v, done: false, dueDate: '', priority: 'normal', subtasks: [], note: '', order: maxOrder + 1, completeDate: '' }]);
    saveState(); renderLife();
    var inp = $('lifeQuickInput'); if (inp) inp.focus();
    renderOverview();
  }
  function bindLifeDetail() {
    var input = $('lifeQuickInput');
    if (input) input.onkeydown = function (e) { if (e.key === 'Enter') { e.preventDefault(); lifeQuickAdd(); } };
    var box = $('lifeItems');
    if (!box) return;
    var dragId = null;
    Array.prototype.forEach.call(box.querySelectorAll('.life-item'), function (el) {
      el.addEventListener('dragstart', function () { dragId = el.getAttribute('data-id'); el.classList.add('dragging'); });
      el.addEventListener('dragend', function () { el.classList.remove('dragging'); });
      el.addEventListener('dragover', function (e) { e.preventDefault(); });
      el.addEventListener('drop', function (e) { e.preventDefault(); var tid = el.getAttribute('data-id'); if (dragId && tid !== dragId) moveLifeItem(dragId, tid); });
    });
  }

  function openLifeListModal(id) {
    var editingList = id ? (state.lifeLists || []).find(function (l) { return l.id === id; }) : null;
    var name = editingList ? editingList.name : '';
    var icon = editingList ? (editingList.icon || '📌') : '📌';
    var color = editingList ? (editingList.color || '#D4B8A8') : LIFE_COLORS[(state.lifeLists || []).length % LIFE_COLORS.length];
    var group = editingList ? (editingList.group || '') : '';
    var groups = state.lifeGroups || [];
    $('modalTitle').textContent = editingList ? '编辑清单' : '新建清单';
    var iconOpts = LIFE_ICONS.map(function (ic) { return '<option value="' + ic + '"' + (ic === icon ? ' selected' : '') + '>' + ic + '</option>'; }).join('');
    var groupOpts = '<option value="">不分组</option>' + groups.map(function (g) { return '<option value="' + esc(g) + '"' + (g === group ? ' selected' : '') + '>' + esc(g) + '</option>'; }).join('') + '<option value="__new__">＋ 新建分组…</option>';
    var colorOpts = LIFE_COLORS.map(function (c) { return '<span class="life-color-dot' + (c === color ? ' on' : '') + '" data-color="' + c + '" style="background:' + c + '"></span>'; }).join('');
    $('modalBody').innerHTML =
      '<label>清单名称 *<input type="text" id="ll-name" value="' + esc(name) + '" placeholder="如 购物清单" /></label>' +
      '<label>清单图标<select id="ll-icon">' + iconOpts + '</select></label>' +
      '<label>所属分组<select id="ll-group">' + groupOpts + '</select></label>' +
      '<label id="ll-newgroup-wrap" hidden>新建分组名称<input type="text" id="ll-newgroup" placeholder="如 家庭" /></label>' +
      '<div class="life-color-label">清单颜色</div><div class="life-colors" id="ll-colors">' + colorOpts + '</div>' +
      '<div class="modal-actions"><button class="btn primary" id="llSave">' + (editingList ? '保存' : '创建') + '</button><button class="btn ghost" id="llCancel">取消</button></div>';
    var selectedColor = color;
    Array.prototype.forEach.call($('ll-colors').querySelectorAll('.life-color-dot'), function (dot) {
      dot.onclick = function () {
        selectedColor = dot.getAttribute('data-color');
        Array.prototype.forEach.call($('ll-colors').querySelectorAll('.life-color-dot'), function (d) { d.classList.toggle('on', d === dot); });
      };
    });
    $('ll-group').onchange = function () { $('ll-newgroup-wrap').hidden = (this.value !== '__new__'); };
    $('llSave').onclick = function () {
      var nm = $('ll-name').value.trim();
      if (!nm) { toast('请填写清单名称', 'err'); return; }
      var grp = $('ll-group').value;
      if (grp === '__new__') { grp = $('ll-newgroup').value.trim(); if (!grp) { toast('请填写分组名称', 'err'); return; } }
      if (grp && (state.lifeGroups || []).indexOf(grp) < 0) state.lifeGroups = (state.lifeGroups || []).concat([grp]);
      if (editingList) {
        editingList.name = nm; editingList.icon = $('ll-icon').value; editingList.color = selectedColor; editingList.group = grp || '';
        saveState(); closeModal(); renderLife(); toast('清单已更新', 'ok');
      } else {
        var maxOrder = (state.lifeLists || []).reduce(function (m, l) { return Math.max(m, l.order || 0); }, 0);
        state.lifeLists = (state.lifeLists || []).concat([{ id: uid(), name: nm, icon: $('ll-icon').value, group: grp || '', color: selectedColor, order: maxOrder + 1 }]);
        saveState(); closeModal(); renderLife(); renderOverview(); toast('✨ 清单已创建', 'ok');
      }
    };
    $('llCancel').onclick = closeModal;
    showModal();
  }

  function openLifeItemModal(id, listId) {
    var editingItem = id ? (state.lifeItems || []).find(function (i) { return i.id === id; }) : null;
    var content = editingItem ? editingItem.content : '';
    var due = editingItem ? (editingItem.dueDate || '') : '';
    var prio = editingItem ? (editingItem.priority || 'normal') : 'normal';
    var note = editingItem ? (editingItem.note || '') : '';
    var subs = editingItem ? (editingItem.subtasks || []).slice() : [];
    var lid = editingItem ? editingItem.listId : (listId || lifeSelList);
    $('modalTitle').textContent = editingItem ? '编辑事项' : '添加事项';
    $('modalBody').innerHTML =
      '<label>事项内容 *<input type="text" id="li-content" value="' + esc(content) + '" placeholder="想做的事" /></label>' +
      '<div class="life-row2">' +
        '<label>截止日期<input type="date" id="li-due" value="' + esc(due) + '" /></label>' +
        '<label>优先级<select id="li-prio"><option value="normal"' + (prio === 'normal' ? ' selected' : '') + '>普通</option><option value="important"' + (prio === 'important' ? ' selected' : '') + '>⭐️ 重要</option></select></label>' +
      '</div>' +
      '<label>详细描述<textarea id="li-note" rows="2" placeholder="备注…">' + esc(note) + '</textarea></label>' +
      '<div class="life-sub-title">子任务</div>' +
      '<div class="life-subs" id="liSubs"></div>' +
      '<div class="life-sub-add"><input type="text" id="liSubInput" placeholder="添加子任务，回车保存" /><button class="btn ghost sm" id="liSubAdd">＋</button></div>' +
      '<div class="modal-actions"><button class="btn primary" id="liSave">' + (editingItem ? '保存' : '添加') + '</button><button class="btn ghost" id="liCancel">取消</button></div>';
    function renderSubs() {
      $('liSubs').innerHTML = subs.map(function (s, idx) {
        return '<div class="life-sub' + (s.done ? ' done' : '') + '" data-idx="' + idx + '">' +
          '<button class="check-btn' + (s.done ? ' on' : '') + '" data-subtoggle="' + idx + '"></button>' +
          '<span class="life-sub-text">' + esc(s.content) + '</span>' +
          '<button class="icon-btn" data-subdel="' + idx + '" title="删除">✕</button>' +
        '</div>';
      }).join('');
      Array.prototype.forEach.call($('liSubs').querySelectorAll('[data-subtoggle]'), function (b) {
        b.onclick = function () { var k = +b.getAttribute('data-subtoggle'); subs[k].done = !subs[k].done; renderSubs(); };
      });
      Array.prototype.forEach.call($('liSubs').querySelectorAll('[data-subdel]'), function (b) {
        b.onclick = function () { var k = +b.getAttribute('data-subdel'); subs.splice(k, 1); renderSubs(); };
      });
    }
    function addSub() {
      var v = $('liSubInput').value.trim(); if (!v) return;
      subs.push({ id: uid(), content: v, done: false });
      $('liSubInput').value = ''; renderSubs();
    }
    renderSubs();
    $('liSubAdd').onclick = addSub;
    $('liSubInput').onkeydown = function (e) { if (e.key === 'Enter') { e.preventDefault(); addSub(); } };
    $('liSave').onclick = function () {
      var c = $('li-content').value.trim();
      if (!c) { toast('请填写事项内容', 'err'); return; }
      if (editingItem) {
        editingItem.content = c; editingItem.dueDate = $('li-due').value || ''; editingItem.priority = $('li-prio').value;
        editingItem.note = $('li-note').value.trim(); editingItem.subtasks = subs;
        saveState(); closeModal(); renderLife(); renderOverview(); toast('已保存', 'ok');
      } else {
        var maxOrder = (state.lifeItems || []).filter(function (i) { return i.listId === lid; }).reduce(function (m, i) { return Math.max(m, i.order || 0); }, 0);
        state.lifeItems = (state.lifeItems || []).concat([{ id: uid(), listId: lid, content: c, done: false, dueDate: $('li-due').value || '', priority: $('li-prio').value, subtasks: subs, note: $('li-note').value.trim(), order: maxOrder + 1, completeDate: '' }]);
        saveState(); closeModal(); renderLife(); renderOverview(); toast('已添加', 'ok');
      }
    };
    $('liCancel').onclick = closeModal;
    showModal();
  }

  function saveLifeTemplate(listId) {
    var l = (state.lifeLists || []).find(function (x) { return x.id === listId; });
    if (!l) return;
    var items = lifeItemsOf(listId).map(function (i) {
      return { content: i.content, dueDate: i.dueDate || '', priority: i.priority || 'normal', note: i.note || '', subtasks: (i.subtasks || []).map(function (s) { return { content: s.content, done: false }; }) };
    });
    state.lifeTemplates = (state.lifeTemplates || []).concat([{ id: uid(), name: l.name, icon: l.icon || '📋', color: l.color || '#D4B8A8', items: items }]);
    saveState(); toast('📋 已保存为模板', 'ok'); renderLife();
  }
  function useLifeTemplate(id) {
    var t = (state.lifeTemplates || []).find(function (x) { return x.id === id; });
    if (!t) return;
    var maxOrder = (state.lifeLists || []).reduce(function (m, l) { return Math.max(m, l.order || 0); }, 0);
    var newList = { id: uid(), name: t.name + ' 副本', icon: t.icon || '📋', group: '', color: t.color || '#D4B8A8', order: maxOrder + 1 };
    state.lifeLists = (state.lifeLists || []).concat([newList]);
    var k = 0;
    (t.items || []).forEach(function (it) {
      state.lifeItems = (state.lifeItems || []).concat([{ id: uid(), listId: newList.id, content: it.content, done: false, dueDate: it.dueDate || '', priority: it.priority || 'normal', subtasks: (it.subtasks || []).map(function (s) { return { id: uid(), content: s.content, done: false }; }), note: it.note || '', order: k + 1, completeDate: '' }]);
      k++;
    });
    saveState(); lifeView = 'all'; lifeSelList = newList.id; renderLife(); renderOverview(); toast('📋 模板已使用，已创建新清单', 'ok');
  }
  function deleteLifeTemplate(id) {
    if (!confirmDel('确定删除该模板吗？')) return;
    state.lifeTemplates = (state.lifeTemplates || []).filter(function (x) { return x.id !== id; });
    saveState(); renderLife();
  }
  function renameLifeTemplate(id) {
    var t = (state.lifeTemplates || []).find(function (x) { return x.id === id; });
    if (!t) return;
    openTextModal('重命名模板', t.name, function (v) { if (!v) return; t.name = v; saveState(); renderLife(); toast('已重命名', 'ok'); });
  }
  function openTextModal(title, val, cb) {
    $('modalTitle').textContent = title;
    $('modalBody').innerHTML =
      '<label>名称<input type="text" id="tm-text" value="' + esc(val) + '" /></label>' +
      '<div class="modal-actions"><button class="btn primary" id="tmOk">确定</button><button class="btn ghost" id="tmCancel">取消</button></div>';
    $('tmOk').onclick = function () { closeModal(); cb($('tm-text').value.trim()); };
    $('tmCancel').onclick = closeModal;
    showModal();
  }

  function openLifeAddMenu() {
    $('modalTitle').textContent = '添加';
    $('modalBody').innerHTML =
      '<div class="life-add-menu">' +
        '<button class="btn primary block" id="lamNew">📝 新建清单</button>' +
        '<button class="btn ghost block" id="lamTmpl">📋 使用模板</button>' +
      '</div>' +
      '<div class="modal-actions"><button class="btn ghost" id="lamCancel">取消</button></div>';
    $('lamNew').onclick = function () { closeModal(); openLifeListModal(); };
    $('lamTmpl').onclick = function () { closeModal(); lifeView = 'all'; lifeSelList = null; renderLife(); toast('请在下方「我的模板」中选择', 'ok'); };
    $('lamCancel').onclick = closeModal;
    showModal();
  }

  function openLifeStatModal() {
    var lists = state.lifeLists || [];
    var items = state.lifeItems || [];
    var total = items.length;
    var done = items.filter(function (i) { return i.done; }).length;
    var pct = total ? Math.round(done / total * 100) : 0;
    var ring = lifeDonutRing(done, total);
    var ym = TODAY.slice(0, 7);
    var days = [];
    for (var d = 1; d <= 31; d++) { var ds = ym + '-' + pad(d); days.push({ d: ds, c: items.filter(function (i) { return i.done && i.completeDate === ds; }).length }); }
    var maxC = Math.max(1, days.reduce(function (m, x) { return Math.max(m, x.c); }, 0));
    var bars = days.map(function (x) { return '<div class="life-bar-col"><div class="life-bar" style="height:' + (x.c / maxC * 60) + 'px"></div><div class="life-bar-d">' + (+x.d.slice(8)) + '</div></div>'; }).join('');
    var ranked = lists.map(function (l) { var pr = lifeProgress(l.id); return { name: l.name, icon: l.icon, pct: pr.pct, done: pr.done, total: pr.total }; }).sort(function (a, b) { return b.pct - a.pct; });
    var rankHtml = ranked.map(function (r) { return '<div class="life-rank-row"><span>' + esc(r.icon || '📌') + ' ' + esc(r.name) + '</span><span class="life-rank-pct">' + r.pct + '%（' + r.done + '/' + r.total + '）</span></div>'; }).join('');
    $('modalTitle').textContent = '生活清单 · 统计';
    $('modalBody').innerHTML =
      '<div class="life-stat-grid">' +
        '<div class="life-stat-box"><div class="k">总清单</div><div class="v">' + lists.length + '</div></div>' +
        '<div class="life-stat-box"><div class="k">总事项</div><div class="v">' + total + '</div></div>' +
        '<div class="life-stat-box"><div class="k">已完成</div><div class="v">' + done + '</div></div>' +
      '</div>' +
      '<div class="life-stat-section"><div class="rep-title">总体完成率</div><div class="life-ring-wrap">' + ring + '<div class="life-ring-pct">' + pct + '%</div></div></div>' +
      '<div class="life-stat-section"><div class="rep-title">本月完成趋势（按日）</div><div class="life-bars">' + bars + '</div></div>' +
      '<div class="life-stat-section"><div class="rep-title">清单完成排行</div>' + (ranked.length ? rankHtml : '<div class="muted-tip">暂无清单</div>') + '</div>' +
      '<div class="modal-actions"><button class="btn ghost" id="lsClose">关闭</button></div>';
    $('lsClose').onclick = closeModal;
    showModal();
  }
  function lifeDonutRing(done, total) {
    var pct = total ? done / total : 0;
    var r = 42, c = 2 * Math.PI * r;
    var off = c * (1 - pct);
    return '<svg width="110" height="110" viewBox="0 0 110 110"><circle cx="55" cy="55" r="' + r + '" fill="none" stroke="#EEE7E0" stroke-width="10"/>' +
      '<circle cx="55" cy="55" r="' + r + '" fill="none" stroke="var(--primary)" stroke-width="10" stroke-linecap="round" stroke-dasharray="' + c + '" stroke-dashoffset="' + off + '" transform="rotate(-90 55 55)"/></svg>';
  }

  function migrateLife() {
    if (!state.life || !state.life.length) return;
    var lists = [], items = [];
    var cats = [];
    state.life.forEach(function (l) { if (cats.indexOf(l.category) < 0) cats.push(l.category); });
    cats.forEach(function (cat, idx) {
      var lid = uid();
      lists.push({ id: lid, name: cat, icon: '📌', group: '', color: LIFE_COLORS[idx % LIFE_COLORS.length], order: idx });
      state.life.filter(function (l) { return l.category === cat; }).forEach(function (l) {
        items.push({ id: uid(), listId: lid, content: l.content, done: !!l.done, dueDate: l.targetDate || '', priority: 'normal', subtasks: [], note: '', order: 0, completeDate: l.done ? TODAY : '' });
      });
    });
    state.lifeLists = lists; state.lifeItems = items; state.lifeGroups = []; state.lifeTemplates = [];
    state.life = [];
    saveState();
  }

  /* ============ 模块9：旅游 ============ */
  function renderTravel() {
    var list = state.travel.slice().sort(function (a, b) { return a.startDate < b.startDate ? 1 : a.startDate > b.startDate ? -1 : 0; });
    var box = $('travelList');
    if (!list.length) { box.innerHTML = emptyState('🗺️', '还没有旅行记录，去远方吧'); return; }
    box.innerHTML = list.map(function (t) {
      var extra = [];
      if (t.companion) extra.push('同行 ' + esc(t.companion));
      if (t.cost) extra.push('¥' + t.cost);
      if (t.note) extra.push(esc(t.note));
      return itemHTML(t.id, 'travel',
        '<span>' + esc(t.destination) + '</span><span class="tag">' + t.days + ' 天</span>',
        esc(t.startDate) + ' ~ ' + esc(t.endDate) + (extra.length ? ' · ' + extra.join(' · ') : ''));
    }).join('');
  }
  function submitTravel() {
    var dest = $('tr-dest').value.trim();
    var start = $('tr-start').value, end = $('tr-end').value;
    if (!dest) { toast('请填写目的地', 'err'); return; }
    if (!start || !end) { toast('请选择出发与结束日期', 'err'); return; }
    if (end < start) { toast('结束日期不能早于出发日期', 'err'); return; }
    var days = Math.round((new Date(end) - new Date(start)) / 86400000) + 1;
    var rec = { id: uid(), destination: dest, startDate: start, endDate: end, companion: $('tr-companion').value.trim(), days: days, cost: num($('tr-cost').value), note: $('tr-note').value.trim() };
    if (editing.travel) {
      var i = state.travel.findIndex(function (x) { return x.id === editing.travel; });
      if (i >= 0) state.travel[i] = Object.assign(state.travel[i], rec, { id: editing.travel });
      cancelEdit('travel');
    } else { state.travel.push(rec); flashOk($('tr-submit')); }
    saveState(); clearForm('travel'); renderTravel();
  }

  /* ============ 列表项 HTML & 通用删除/编辑 ============ */
  function itemHTML(id, mod, head, line2) {
    return '<div class="item" data-id="' + id + '">' +
      '<div class="body"><div class="line1">' + head + '</div><div class="line2">' + line2 + '</div></div>' +
      '<div class="ops"><button class="icon-btn" data-act="edit" data-mod="' + mod + '" title="编辑">✏️</button>' +
      '<button class="icon-btn" data-act="del" data-mod="' + mod + '" title="删除">🗑️</button></div></div>';
  }
  function emptyState(em, text) { return '<div class="empty"><span class="em">' + em + '</span>' + text + '</div>'; }

  function fillForm(mod, rec) {
    var map = { exercise: 'e', meal: 'm', weight: 'w', finance: 'f', plan: 'p', todo: 't', travel: 'tr' };
    var p = map[mod];
    if (mod === 'exercise') {
      $('e-date').value = rec.date; $('e-type').value = rec.type; $('e-duration').value = rec.duration;
      $('e-calories').value = rec.calories || ''; $('e-feeling').value = rec.feeling || '';
    } else if (mod === 'finance') {
      $('f-date').value = rec.date; setRadio('f-type', rec.type); $('f-category').value = rec.category;
      $('f-amount').value = rec.amount; $('f-pay').value = rec.payMethod; $('f-note').value = rec.note || '';
    } else if (mod === 'plan') {
      $('p-time').value = rec.time || ''; $('p-content').value = rec.content; $('p-priority').value = rec.priority;
    } else if (mod === 'todo') {
      $('t-due').value = rec.dueDate; $('t-content').value = rec.content; $('t-project').value = rec.project || '';
      $('t-priority').value = rec.priority; $('t-status').value = rec.status;
    } else if (mod === 'travel') {
      $('tr-dest').value = rec.destination; $('tr-start').value = rec.startDate; $('tr-end').value = rec.endDate;
      $('tr-companion').value = rec.companion || ''; $('tr-cost').value = rec.cost || ''; $('tr-note').value = rec.note || '';
    }
  }
  function clearForm(mod) {
    var map = { exercise: 'e', meal: 'm', weight: 'w', finance: 'f', plan: 'p', todo: 't', travel: 'tr' };
    var p = map[mod];
    var ids = {
      e: ['e-date', 'e-duration', 'e-calories', 'e-feeling'],
      m: [], w: [],
      f: ['f-date', 'f-amount', 'f-note'], p: ['p-time', 'p-content'],
      t: ['t-due', 't-content', 't-project'],
      tr: ['tr-dest', 'tr-companion', 'tr-cost', 'tr-note']
    }[p];
    ids.forEach(function (id) { if ($(id)) $(id).value = ''; });
    // 日期字段重置为今天
    if ($('e-date')) $('e-date').value = TODAY;
    if ($('f-date')) $('f-date').value = TODAY;
  }
  function deleteRec(mod, id) {
    if (!confirmDel()) return;
    state[mod] = state[mod].filter(function (x) { return x.id !== id; });
    saveState(); rerender(mod);
  }
  function rerender(mod) {
    ({ reading: renderReading, exercise: renderExercise, meal: renderMeal, weight: renderWeight,
      finance: renderFinance, todo: renderTodo, travel: renderTravel })[mod]();
  }

  /* ============ 总览 ============ */
  function renderOverview() {
    var h = new Date().getHours();
    var greet = h < 11 ? '早上好 🌤️' : h < 18 ? '下午好 ☀️' : '晚上好 🌙';
    $('ovGreet').textContent = greet + '，倩崽';

    var plans = state.plan.filter(function (p) { return p.date === TODAY; });
    var pDone = plans.filter(function (p) { return p.status === '已完成'; }).length;
    var todos = state.todo.filter(function (t) { return !t.isArchived; });
    var overdue = todos.filter(function (t) { return t.status === '已延期'; }).length;
    var eCount = state.exercise.filter(function (e) { return e.date === TODAY; }).length;
    var mCount = state.meal.filter(function (m) { return m.date === TODAY; }).length;
    var todayChores = getChoresForDate(new Date());
    var choreDone = todayChores.filter(function (c) { return choreIsDone(new Date(), c.key); }).length;
    var latestW = state.weight.slice().sort(function (a, b) { return a.date < b.date ? 1 : -1; })[0];
    var rDone = finishedThisYear().length;
    var rGoal = state.readingGoal || 24;

    var cells = [
      { k: '待办计划', v: todos.length + ' 项（逾期 ' + overdue + ' 项）' },
      { k: '今年已读', v: rDone + ' / ' + rGoal + ' 本' },
      { k: '今日锻炼', v: eCount + ' 次' },
      { k: '今日吃饭', v: mCount + ' 餐' },
      { k: '今日家务', v: choreDone + ' / ' + todayChores.length + ' 项' },
      { k: '最新体重', v: latestW ? latestW.weight + ' kg' : '暂无' }
    ];
    $('ovGrid').innerHTML = cells.map(function (c) {
      return '<div class="ov-cell"><div class="k">' + c.k + '</div><div class="v">' + esc(c.v) + '</div></div>';
    }).join('');
  }

  /* ============ 导出 / 导入 ============ */
  function exportData() {
    var payload = { _app: 'qianzai_workbench', _version: 1, _exportedAt: new Date().toISOString(), data: state };
    var blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'qianzai-workbench-' + TODAY + '.json';
    a.click();
    URL.revokeObjectURL(a.href);
    toast('已导出数据', 'ok');
  }
  function importData(file) {
    if (!window.confirm('此操作将覆盖现有数据，是否继续？')) return;
    var reader = new FileReader();
    reader.onload = function () {
      try {
        var obj = JSON.parse(reader.result);
        var data = obj.data || obj;
        for (var k in EMPTY) {
          if (Array.isArray(EMPTY[k])) state[k] = Array.isArray(data[k]) ? data[k] : [];
          else state[k] = (data[k] !== undefined ? data[k] : EMPTY[k]);
        }
        saveState();
        renderAll();
        toast('导入成功', 'ok');
      } catch (e) { toast('文件解析失败', 'err'); }
    };
    reader.readAsText(file);
  }

  // 清空全部记账记录（用于误导入后彻底清除）
  function clearFinance() {
    if (!state.finance || !state.finance.length) { toast('记账记录已经是空的', 'ok'); return; }
    if (!window.confirm('确定清空全部 ' + state.finance.length + ' 条记账记录吗？\n此操作不可恢复，且会同步到云端。')) return;
    state.finance = [];
    saveState(); renderFinance();
    toast('已清空全部记账记录', 'ok');
  }

  /* ============ 事件绑定 ============ */
  function bind() {
    // 导航
    document.querySelectorAll('[data-nav]').forEach(function (el) {
      el.addEventListener('click', function () { goPanel(el.getAttribute('data-nav')); });
    });

    // 云端同步药丸：点击立即同步 / 设置
    var pill = $('cloudPill'); if (pill) pill.addEventListener('click', function () { CloudSync.enableFromPill(); });

    // 各模块提交
    $('t-submit').addEventListener('click', submitTodo);
    $('tr-submit').addEventListener('click', submitTravel);

    // 取消编辑
    ['e', 'm', 'w', 'f', 't', 'tr'].forEach(function (p) {
      var c = $(p + '-cancel'); if (c) c.addEventListener('click', function () {
        var mod = { r: 'reading', e: 'exercise', m: 'meal', w: 'weight', f: 'finance', t: 'todo', tr: 'travel' }[p];
        cancelEdit(mod); clearForm(mod);
      });
    });

    // 列表事件委托（编辑/删除/状态切换/复选）
    document.querySelector('.panels').addEventListener('click', function (e) {
      var btn = e.target.closest('[data-act]'); if (!btn) return;
      var act = btn.getAttribute('data-act');
      if (act === 'back-detail') { closeDetail(); return; }
      if (act === 'add-note-for') { var forId = btn.closest('[data-id]').getAttribute('data-id'); openNoteModal(forId); return; }
      if (act === 'year') { openYearModal(); return; }
      if (act === 'goal') { openGoalModal(); return; }
      if (act === 'ex-quick') { openExerciseModal(null, 'quick'); return; }
      if (act === 'ex-goal') { openExerciseGoalModal(); return; }
      if (act === 'ex-day') { exSelDate = btn.getAttribute('data-day'); renderExerciseCalendar(); return; }
      if (act === 'ex-all') { exSelDate = null; renderExerciseCalendar(); return; }
      if (act === 'chore-toggle') { toggleChore(btn.getAttribute('data-cdate'), btn.getAttribute('data-ckey')); return; }
      if (act === 'chore-set') { openChoreMemberModal(); return; }
      var mod = btn.getAttribute('data-mod');
      var idEl = btn.closest('[data-id]'); var id = idEl ? idEl.getAttribute('data-id') : null;
      if (mod === 'book') {
        if (act === 'detail') openBookDetail(id);
        else if (act === 'edit-book') openBookModal(id);
        else if (act === 'del-book') deleteBook(id);
        else if (act === 'start') markStatus(id, '正在读');
        else if (act === 'finish') markStatus(id, '读完');
        return;
      }
      if (mod === 'note') {
        if (act === 'edit-note') openNoteModal(null, id);
        else if (act === 'del-note') deleteNote(id);
        return;
      }
      if (mod === 'tx') { if (act === 'edit') openTxModal(id); else if (act === 'del') deleteTx(id); return; }
      if (mod === 'acct') { if (act === 'edit') openAcctModal(id); else if (act === 'del') deleteAcct(id); return; }
      if (mod === 'bud') { if (act === 'edit') openBudModal(id); else if (act === 'del') deleteBud(id); return; }
      if (mod === 'weight') { if (act === 'edit') openWeightModal(id); else if (act === 'del') deleteRec('weight', id); return; }
      if (mod === 'meal') { if (act === 'edit') openMealModal(id); else if (act === 'del') deleteRec('meal', id); return; }
      if (mod === 'exercise') { if (act === 'edit') openExerciseModal(id); else if (act === 'del') deleteRec('exercise', id); return; }
      if (act === 'edit') {
        var rec = state[mod].find(function (x) { return x.id === id; });
        if (rec) { startEdit(mod, id); fillForm(mod, rec); goPanel(mod); window.scrollTo(0, 0); }
      } else if (act === 'del') { deleteRec(mod, id); }
      else if (act === 'cycle') { cyclePlan(id); }
    });
    // 待办状态下拉
    document.querySelector('.panels').addEventListener('change', function (e) {
      var sel = e.target.closest('[data-act="status"]');
      if (sel) setTodoStatus(sel.getAttribute('data-id'), sel.value);
    });

    // 历史/归档开关
    $('tShowArchived').addEventListener('change', renderTodo);

    // 导出/导入
    $('exportBtn').addEventListener('click', exportData);
    $('importBtn').addEventListener('click', function () { $('importFile').click(); });
    $('importFile').addEventListener('change', function (e) { if (e.target.files[0]) importData(e.target.files[0]); e.target.value = ''; });

    // 设置表单标题默认值
    ['e', 'm', 'w', 'p', 't', 'tr'].forEach(function (p) {
      var t = $(p + '-FormTitle'); if (t) t.setAttribute('data-default', t.textContent);
    });

    // ===== 理财模块 =====
    document.querySelectorAll('[data-fin-tab]').forEach(function (b) {
      b.addEventListener('click', function () { financeTab = b.getAttribute('data-fin-tab'); renderFinance(); });
    });
    $('finAddBtn').addEventListener('click', function () { openTxModal(); });
    $('finClearBtn').addEventListener('click', clearFinance);
    $('finAddAcctBtn').addEventListener('click', function () { openAcctModal(); });
    $('finAddBudBtn').addEventListener('click', function () { openBudModal(); });
    $('modalClose').addEventListener('click', closeModal);
    $('modalOverlay').addEventListener('click', function (e) { if (e.target === $('modalOverlay')) closeModal(); });

    $('finFilterType').addEventListener('change', function () { finFilter.type = this.value; renderFlow(); });
    $('finFilterCat').addEventListener('change', function () { finFilter.cat = this.value; renderFlow(); });
    $('finFilterAcct').addEventListener('change', function () { finFilter.acct = this.value; renderFlow(); });
    $('finRangeSeg').addEventListener('click', function (e) {
      var b = e.target.closest('[data-range]'); if (!b) return;
      finFilter.range = b.getAttribute('data-range');
      setSegActive($('finRangeSeg'), b);
      var custom = finFilter.range === 'custom';
      $('finRangeStart').hidden = !custom; $('finRangeEnd').hidden = !custom;
      renderFlow();
    });
    $('finRangeStart').addEventListener('change', renderFlow);
    $('finRangeEnd').addEventListener('change', renderFlow);
    $('budCycle').addEventListener('change', renderBudgets);

    $('repFilterAcct').addEventListener('change', function () { repFilter.acct = this.value; renderReport(); });
    $('repRangeSeg').addEventListener('click', function (e) {
      var b = e.target.closest('[data-range]'); if (!b) return;
      repFilter.range = b.getAttribute('data-range');
      setSegActive($('repRangeSeg'), b);
      var custom = repFilter.range === 'custom';
      $('repRangeStart').hidden = !custom; $('repRangeEnd').hidden = !custom;
      renderReport();
    });
    $('repRangeStart').addEventListener('change', renderReport);
    $('repRangeEnd').addEventListener('change', renderReport);

    // ===== 体重模块 =====
    $('wFab').addEventListener('click', function () { openWeightModal(); });
    $('wExportBtn').addEventListener('click', exportWeightCsv);
    document.querySelectorAll('[data-wtab]').forEach(function (b) {
      b.addEventListener('click', function () { weightTab = b.getAttribute('data-wtab'); renderWeight(); });
    });
    $('wTrendSeg').addEventListener('click', function (e) {
      var b = e.target.closest('[data-range]'); if (!b) return;
      wTrendRange = b.getAttribute('data-range');
      setSegActive($('wTrendSeg'), b); renderWeightChart();
    });

    // ===== 好好吃饭模块 =====
    $('mealFab').addEventListener('click', function () { openMealModal(); });
    $('nutriTargetBtn').addEventListener('click', openMealTargetModal);
    document.querySelectorAll('[data-mtab]').forEach(function (b) {
      b.addEventListener('click', function () { mealMode = b.getAttribute('data-mtab'); mealSelDate = null; renderMeal(); });
    });
    $('diaryViewSeg').addEventListener('click', function (e) {
      var b = e.target.closest('[data-dview]'); if (!b) return;
      diaryView = b.getAttribute('data-dview'); renderMeal();
    });
    $('checkViewSeg').addEventListener('click', function (e) {
      var b = e.target.closest('[data-cview]'); if (!b) return;
      checkView = b.getAttribute('data-cview'); renderMeal();
    });

    // ===== 每月阅读模块 =====
    $('rdFab').addEventListener('click', function () {
      var activeTab = document.querySelector('#rdTabs .active');
      if (activeTab && activeTab.dataset.rdtab === 'notes') { openNoteModal(); }
      else { openBookModal(); }
    });
    document.querySelectorAll('[data-rdtab]').forEach(function (b) {
      b.addEventListener('click', function () { readingTab = b.getAttribute('data-rdtab'); renderReading(); });
    });
    $('rdViewSeg').addEventListener('click', function (e) {
      var b = e.target.closest('[data-rview]'); if (!b) return;
      rdView = b.getAttribute('data-rview'); setSegActive($('rdViewSeg'), b); renderReading();
    });
    $('rdNoteViewSeg').addEventListener('click', function (e) {
      var b = e.target.closest('[data-nview]'); if (!b) return;
      rdNoteView = b.getAttribute('data-nview'); setSegActive($('rdNoteViewSeg'), b); renderReading();
    });

    // ===== 锻炼身体模块 =====
    $('exFab').addEventListener('click', function () { openExerciseModal(); });
    $('exRangeSeg').addEventListener('click', function (e) {
      var b = e.target.closest('[data-range]'); if (!b) return;
      exRange = b.getAttribute('data-range'); setSegActive($('exRangeSeg'), b); renderExerciseStats();
    });
  }

  function renderAll() {
    renderReading(); renderExercise(); renderMeal(); renderWeight(); renderFinance();
    renderTodo(); renderTravel(); renderChores(); renderOverview();
  }

  /* ============ 家务排班（沿用家庭管家排班引擎，成员可配置） ============ */
  var CHORE_NAMES = { cook: '做饭', wash: '洗碗', sweep: '扫地+拖地', trash: '倒垃圾', fridge: '清理冰箱', laundry: '洗衣服', deepclean: '大扫除' };
  var CHORE_ICON = { cook: '🍳', wash: '🥣', sweep: '🧹', trash: '🗑️', fridge: '🧊', laundry: '🧺', deepclean: '✨' };
  var WD_MON = ['一', '二', '三', '四', '五', '六', '日'];

  function daysInMonth(y, m) { return new Date(y, m + 1, 0).getDate(); }
  function isLastSunday(d) { return d.getDay() === 0 && (d.getDate() + 7 > daysInMonth(d.getFullYear(), d.getMonth())); }
  function startOfWeek(d) { var x = new Date(d.getFullYear(), d.getMonth(), d.getDate()); var wd = (x.getDay() + 6) % 7; x.setDate(x.getDate() - wd); return x; }
  function weekdayName(d) { return '周' + WD_MON[(d.getDay() + 6) % 7]; }
  function isSameDay(a, b) { return fmtDate(a) === fmtDate(b); }
  function choreMember(id) {
    var ms = state.choreMembers || [];
    var m = ms.filter(function (x) { return x.id === id; })[0];
    return m || { id: id, name: id, color: '#B6A6C9' };
  }
  function bothMembers() { var a = choreMember('a'), b = choreMember('b'); return { a: a, b: b, name: a.name + '·' + b.name, color: '#B6A6C9' }; }

  // 排班引擎：按星期几 / 日期奇偶 / 月末周日分配，成员 a/b 对应可配置两人
  function getChoresForDate(d) {
    var day = d.getDay();
    var weekend = (day === 0 || day === 6);
    var out = [];
    out.push({ key: 'cook', who: weekend ? 'b' : 'a' });
    out.push({ key: 'wash', who: weekend ? 'a' : 'b' });
    out.push({ key: 'sweep', who: weekend ? 'a' : 'b' });
    out.push({ key: 'trash', who: (d.getDate() % 2 === 0) ? 'a' : 'b' });
    if (day === 6) out.push({ key: 'fridge', who: 'b' });
    if (day === 3 || day === 0) out.push({ key: 'laundry', who: day === 3 ? 'a' : 'b' });
    if (day === 0 && isLastSunday(d)) out.push({ key: 'deepclean', who: 'both' });
    return out;
  }
  function choreIsDone(d, key) { return !!state.choreDone[fmtDate(d) + '|' + key]; }
  function choreSetDone(d, key, v) {
    var k = fmtDate(d) + '|' + key;
    if (v) state.choreDone[k] = 1; else delete state.choreDone[k];
    saveState();
  }
  function choreWhoName(who) { return who === 'both' ? bothMembers().name : choreMember(who).name; }
  function choreWhoColor(who) { return who === 'both' ? '#B6A6C9' : choreMember(who).color; }

  // 本周完成率统计（按成员）
  function choreWeekStats() {
    var ws = startOfWeek(new Date());
    var t = { done: 0, tot: 0 }, a = { done: 0, tot: 0 }, b = { done: 0, tot: 0 };
    for (var i = 0; i < 7; i++) {
      var d = new Date(ws.getFullYear(), ws.getMonth(), ws.getDate() + i);
      getChoresForDate(d).forEach(function (c) {
        var done = choreIsDone(d, c.key);
        t.tot++; if (done) t.done++;
        if (c.who === 'a' || c.who === 'both') { a.tot++; if (done) a.done++; }
        if (c.who === 'b' || c.who === 'both') { b.tot++; if (done) b.done++; }
      });
    }
    return { t: t, a: a, b: b };
  }

  function renderChores() {
    var box = $('choresMain');
    if (!box) return;
    var today = new Date();
    var mA = choreMember('a').name, mB = choreMember('b').name;

    // 本周轮值表（周一~周日）
    var ws = startOfWeek(today);
    var head = '', cols = '';
    for (var i = 0; i < 7; i++) {
      var d = new Date(ws.getFullYear(), ws.getMonth(), ws.getDate() + i);
      head += '<div class="ch-wh' + (isSameDay(d, today) ? ' today' : '') + '"><b>周' + WD_MON[i] + '</b><span class="dnum">' + d.getDate() + '日</span></div>';
      var chips = getChoresForDate(d).map(function (c) {
        var done = choreIsDone(d, c.key);
        return '<div class="ch-chip' + (done ? ' done' : '') + '" style="--cc:' + choreWhoColor(c.who) + '">'
          + '<span class="ch-ic">' + CHORE_ICON[c.key] + '</span>'
          + '<span class="ch-nm">' + CHORE_NAMES[c.key] + '</span>'
          + '<span class="ch-who">' + choreWhoName(c.who) + (done ? ' ✓' : '') + '</span></div>';
      }).join('');
      cols += '<div class="ch-col">' + chips + '</div>';
    }
    var weekView = '<div class="ch-week"><div class="ch-week-head">' + head + '</div><div class="ch-week-cols">' + cols + '</div></div>';

    // 今日待办（可勾选）
    var todayChores = getChoresForDate(today);
    var todo = todayChores.map(function (c) {
      var done = choreIsDone(today, c.key);
      return '<div class="ch-row' + (done ? ' done' : '') + '">'
        + '<div class="chk' + (done ? ' on' : '') + '" data-act="chore-toggle" data-cdate="' + fmtDate(today) + '" data-ckey="' + c.key + '">' + (done ? '✓' : '') + '</div>'
        + '<div class="ch-info"><div class="ch-title">' + CHORE_ICON[c.key] + ' ' + CHORE_NAMES[c.key] + (c.key === 'sweep' ? ' <span class="ch-hint">(扫地拖地一起)</span>' : '') + '</div>'
        + '<div class="ch-meta"><span class="ch-dot" style="background:' + choreWhoColor(c.who) + '"></span>' + choreWhoName(c.who) + '</div></div>'
        + '<span class="ch-state ' + (done ? 'ok' : '') + '">' + (done ? '已完成' : '待做') + '</span></div>';
    }).join('');

    // 统计
    var stt = choreWeekStats();
    var rate = stt.t.tot ? Math.round(stt.t.done / stt.t.tot * 100) : 0;
    var aRate = stt.a.tot ? Math.round(stt.a.done / stt.a.tot * 100) : 0;
    var bRate = stt.b.tot ? Math.round(stt.b.done / stt.b.tot * 100) : 0;
    var todayDone = todayChores.filter(function (c) { return choreIsDone(today, c.key); }).length;
    var summary = '<div class="ch-summary">'
      + '<div class="ch-stat"><div class="num">' + todayDone + '/' + todayChores.length + '</div><div class="lbl">今日完成</div></div>'
      + '<div class="ch-stat"><div class="num">' + rate + '%</div><div class="lbl">本周完成率</div></div>'
      + '<div class="ch-stat"><div class="num">' + mA + ' ' + aRate + '%</div><div class="lbl">' + mA + '完成率</div></div>'
      + '<div class="ch-stat"><div class="num">' + mB + ' ' + bRate + '%</div><div class="lbl">' + mB + '完成率</div></div>'
      + '</div>';

    // 排班规则（动态成员名）
    var rules = [
      '工作日（周一~周五）' + CHORE_NAMES.cook + '由' + mA + '负责，' + CHORE_NAMES.wash + '由' + mB + '负责。',
      '周末（周六~周日）' + CHORE_NAMES.cook + '由' + mB + '负责，' + CHORE_NAMES.wash + '由' + mA + '负责。',
      CHORE_NAMES.sweep + '必须一起进行，已绑定为同一项。',
      CHORE_NAMES.laundry + '每周 2 次（周三、周日）；' + CHORE_NAMES.deepclean + '每月 1 次，安排在休息日，两人共同完成。',
      CHORE_NAMES.trash + '按日期奇偶轮流，' + CHORE_NAMES.fridge + '固定在周六。'
    ].map(function (r) { return '<li>' + esc(r) + '</li>'; }).join('');

    box.innerHTML =
      '<div class="ch-head"><h2>家务排班</h2><button class="btn ghost ch-set" data-act="chore-set">⚙ 设置成员</button></div>'
      + summary
      + '<div class="card"><div class="card-head"><h3>📅 本周轮值表</h3><span class="sub">自动按家庭结构生成</span></div>' + weekView + '</div>'
      + '<div class="card"><div class="card-head"><h3>☀️ 今日待办</h3><span class="sub">' + fmtDate(today) + ' ' + weekdayName(today) + '</span></div>' + (todo || '<div class="empty">今天没有排班 🎉</div>') + '</div>'
      + '<div class="card"><div class="card-head"><h3>📋 排班规则</h3></div><ul class="ch-rules">' + rules + '</ul></div>';
  }

  function toggleChore(dStr, key) {
    var p = dStr.split('-');
    var d = new Date(+p[0], +p[1] - 1, +p[2]);
    var v = !choreIsDone(d, key);
    choreSetDone(d, key, v);
    renderChores(); renderOverview();
    if (v) toast('已完成「' + CHORE_NAMES[key] + '」👍', 'ok');
  }

  function openChoreMemberModal() {
    var a = state.choreMembers[0] || { name: '倩崽', color: '#D4B8A8' };
    var b = state.choreMembers[1] || { name: '胖崽', color: '#7FB1C9' };
    $('modalTitle').textContent = '设置家务成员';
    $('modalBody').innerHTML =
      '<div class="grid-2"><label>成员 A 名称<input type="text" id="cmA-name" value="' + esc(a.name) + '" maxlength="8"></label>'
      + '<label>成员 A 颜色<input type="color" id="cmA-color" value="' + a.color + '"></label></div>'
      + '<div class="grid-2"><label>成员 B 名称<input type="text" id="cmB-name" value="' + esc(b.name) + '" maxlength="8"></label>'
      + '<label>成员 B 颜色<input type="color" id="cmB-color" value="' + b.color + '"></label></div>'
      + '<div class="modal-actions"><button class="btn primary" id="cmSave">保存</button></div>';
    $('cmSave').onclick = function () {
      state.choreMembers = [
        { id: 'a', name: ($('cmA-name').value.trim() || '倩崽'), color: $('cmA-color').value },
        { id: 'b', name: ($('cmB-name').value.trim() || '胖崽'), color: $('cmB-color').value }
      ];
      saveState(); closeModal(); renderChores(); toast('成员已更新', 'ok');
    };
    showModal();
  }

  function choreInit() {
    if (!state.choreMembers || !state.choreMembers.length) {
      state.choreMembers = [ { id: 'a', name: '倩崽', color: '#D4B8A8' }, { id: 'b', name: '胖崽', color: '#7FB1C9' } ];
    }
    if (!state.choreDone || typeof state.choreDone !== 'object' || Array.isArray(state.choreDone)) state.choreDone = {};
    saveState();
  }

  /* ============ 理财：初始化（播种账户 + 旧数据迁移） ============ */
  function finInit() {
    var meta = loadMeta();
    if (!meta.accountsSeeded) {
      state.accounts = [
        { id: uid(), name: '微信零钱', type: '微信支付', init: 0, note: '日常消费' },
        { id: uid(), name: '支付宝', type: '支付宝', init: 0, note: '' },
        { id: uid(), name: '现金', type: '现金', init: 0, note: '' },
        { id: uid(), name: '储蓄卡', type: '银行卡', init: 0, note: '工资卡' },
        { id: uid(), name: '信用卡', type: '信用卡', init: 0, note: '' }
      ];
      meta.accountsSeeded = true; saveMeta(meta); saveState();
    }
    // 迁移旧版理财数据（无 txType 字段）
    if (state.finance.length && !state.finance[0].txType) {
      var pmap = { '微信': '微信支付', '支付宝': '支付宝', '现金': '现金', '信用卡': '信用卡' };
      state.finance = state.finance.map(function (f) {
        var acct = state.accounts.find(function (a) { return a.type === (pmap[f.payMethod] || ''); }) || state.accounts[0];
        return {
          id: f.id || uid(), date: f.date, txType: f.type === '收入' ? '收入' : '支出',
          amount: num(f.amount), catTop: f.category, catSub: f.category,
          account: acct.id, merchant: '', note: f.note || ''
        };
      });
      saveState();
    }
  }

  /* ============ 启动 ============ */
  function init() {
    initDay();
    finInit();
    migrateWeight();
    migrateMeal();
    migrateReading();
    migrateLife();
    choreInit();
    exInit();
    // 默认日期填充
    ['e-date'].forEach(function (id) { if ($(id)) $(id).value = TODAY; });
    // 首次加载导航自动展开 2 秒
    var sb = $('sidebar');
    sb.style.width = '190px'; sb.style.flexBasis = '190px';
    setTimeout(function () { sb.style.width = ''; sb.style.flexBasis = ''; }, 2000);

    tickClock(); setInterval(tickClock, 1000);
    bind();
    renderAll();
    setupDeadlineNotifications();
    goPanel('overview');
    closeModal();
    CloudSync.start();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
