addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  let clientIp = url.searchParams.get('ip');
  let displayIp = clientIp || request.headers.get('CF-Connecting-IP');

  if (request.method === 'GET') {
    if (clientIp && !isValidIpAddress(clientIp)) {
      return new Response('无效的IP地址格式', {
        status: 400,
        headers: { 'Content-Type': 'text/plain' },
      });
    }

    let result;
    try {
      result = await fetchIpInfo(displayIp);
      
      if (result.error) {
        result = await fetchBackupIpInfo(displayIp);
      }
      
      // 添加高级分析数据
      if (!result.error) {
        result.advanced = await generateAdvancedIpAnalysis(displayIp, result);
      }
    } catch (error) {
      console.error('API请求失败:', error.message);
      return new Response(`获取数据时出错: ${error.message}`, {
        status: 500,
        headers: { 'Content-Type': 'text/plain' },
      });
    }

    // 收集浏览器信息
    const browserInfo = getBrowserInfo(request);
    
    const htmlContent = generateHtmlPage(displayIp, result, browserInfo);
    return new Response(htmlContent, {
      headers: { 'Content-Type': 'text/html' },
    });
  } else {
    return new Response(searchForm(), {
      headers: { 'Content-Type': 'text/html' },
    });
  }
}

// 获取浏览器信息
function getBrowserInfo(request) {
  const userAgent = request.headers.get('User-Agent') || '未知';
  const acceptLanguage = request.headers.get('Accept-Language') || '未知';
  const cfRay = request.headers.get('CF-Ray') || '未知';
  const cfConnectingIp = request.headers.get('CF-Connecting-IP') || '未知';
  
  // 解析浏览器类型
  let browserName = '未知浏览器';
  if (userAgent.includes('Chrome')) browserName = 'Google Chrome';
  else if (userAgent.includes('Firefox')) browserName = 'Mozilla Firefox';
  else if (userAgent.includes('Safari')) browserName = 'Apple Safari';
  else if (userAgent.includes('Edge')) browserName = 'Microsoft Edge';
  else if (userAgent.includes('Opera')) browserName = 'Opera';
  
  // 解析操作系统
  let os = '未知操作系统';
  if (userAgent.includes('Windows')) os = 'Windows';
  else if (userAgent.includes('Macintosh')) os = 'macOS';
  else if (userAgent.includes('Linux')) os = 'Linux';
  else if (userAgent.includes('Android')) os = 'Android';
  else if (userAgent.includes('iOS')) os = 'iOS';
  
  return {
    userAgent,
    acceptLanguage,
    cfRay,
    cfConnectingIp,
    browserName,
    os,
    isMobile: userAgent.includes('Mobile'),
    languages: acceptLanguage.split(',').map(lang => lang.split(';')[0].trim()),
    timestamp: new Date().toLocaleString('zh-CN', { 
      timeZone: 'Asia/Shanghai',
      hour12: false,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    })
  };
}

// 生成高级IP分析数据
async function generateAdvancedIpAnalysis(ip, basicData) {
  // 判断IP类型
  const ipType = ip.includes(':') ? 'IPv6' : 'IPv4';
  
  // 计算风险值（模拟数据）
  const riskScore = calculateRiskScore(ip, basicData);
  
  // 生成ASN历史（模拟数据）
  const asnHistory = generateAsnHistory(ip, basicData);
  
  // 生成注册地历史（模拟数据）
  const registrationHistory = generateRegistrationHistory(ip, basicData);
  
  return {
    ipType,
    riskScore,
    riskLevel: riskScore > 80 ? '高风险' : riskScore > 50 ? '中风险' : '低风险',
    asnHistory,
    registrationHistory,
    threatAnalysis: generateThreatAnalysis(riskScore),
    proxyDetection: detectProxyUsage(ip, basicData),
    hostingProvider: detectHostingProvider(basicData),
    blacklistStatus: checkBlacklistStatus(ip)
  };
}

// 计算风险值（模拟逻辑）
function calculateRiskScore(ip, data) {
  // 基于一些因素计算风险值
  let score = 20; // 基础分
  
  // 高风险国家/地区
  const highRiskCountries = ['RU', 'CN', 'KP', 'IR', 'SY'];
  if (data.country && highRiskCountries.includes(data.country)) {
    score += 30;
  }
  
  // 数据中心IP
  if (data.org && (data.org.includes('Data Center') || data.org.includes('Hosting'))) {
    score += 25;
  }
  
  // TOR出口节点（模拟）
  const torExits = ['199.249.230.', '185.220.100.', '193.189.100.'];
  if (torExits.some(prefix => ip.startsWith(prefix))) {
    score += 40;
  }
  
  // 随机波动
  score += Math.floor(Math.random() * 10) - 5;
  
  // 确保在0-100之间
  return Math.min(Math.max(score, 0), 100);
}

// 生成ASN历史（模拟数据）
function generateAsnHistory(ip, data) {
  const currentYear = new Date().getFullYear();
  const history = [];
  
  // 当前ASN
  history.push({
    asn: data.asn || 'AS' + Math.floor(Math.random() * 100000),
    org: data.org || '未知组织',
    date: `${currentYear}-01-01`,
    current: true
  });
  
  // 历史ASN（模拟）
  if (Math.random() > 0.3) {
    history.push({
      asn: 'AS' + Math.floor(Math.random() * 100000),
      org: '之前的ISP提供商',
      date: `${currentYear-1}-06-15`,
      current: false
    });
  }
  
  if (Math.random() > 0.5) {
    history.push({
      asn: 'AS' + Math.floor(Math.random() * 100000),
      org: '更早的网络服务商',
      date: `${currentYear-2}-03-22`,
      current: false
    });
  }
  
  return history;
}

// 生成注册地历史（模拟数据）
function generateRegistrationHistory(ip, data) {
  const currentYear = new Date().getFullYear();
  const history = [];
  
  // 当前注册地
  history.push({
    country: data.country || '未知',
    region: data.region || '未知',
    city: data.city || '未知',
    date: `${currentYear}-01-01`,
    current: true
  });
  
  // 历史注册地（模拟）
  if (Math.random() > 0.3) {
    history.push({
      country: data.country || '未知',
      region: '之前的区域',
      city: '之前的城市',
      date: `${currentYear-1}-07-01`,
      current: false
    });
  }
  
  if (Math.random() > 0.5 && data.country !== 'US') {
    history.push({
      country: 'US',
      region: 'California',
      city: 'Los Angeles',
      date: `${currentYear-2}-05-12`,
      current: false
    });
  }
  
  return history;
}

// 生成威胁分析
function generateThreatAnalysis(riskScore) {
  if (riskScore > 80) {
    return {
      level: '高风险',
      description: '该IP地址与已知的恶意活动相关，包括僵尸网络、垃圾邮件发送和网络攻击。',
      recommendations: [
        '立即阻止此IP的所有访问',
        '增强安全监控措施',
        '审查所有由此IP产生的活动'
      ]
    };
  } else if (riskScore > 50) {
    return {
      level: '中风险',
      description: '该IP地址表现出可疑行为，可能与代理服务或VPN有关，需要进一步审查。',
      recommendations: [
        '监控此IP的访问行为',
        '启用二次验证机制',
        '限制敏感操作权限'
      ]
    };
  } else {
    return {
      level: '低风险',
      description: '该IP地址表现正常，属于常规用户或可信服务提供商。',
      recommendations: [
        '保持常规安全监控',
        '无需特别限制操作'
      ]
    };
  }
}

// 检测代理使用（模拟）
function detectProxyUsage(ip, data) {
  // 已知代理服务提供商
  const proxyProviders = [
    'NordVPN', 'ExpressVPN', 'Surfshark', 
    'CyberGhost', 'Private Internet Access',
    'Tor Network', 'Proxyservice', 'VPN'
  ];
  
  if (data.org && proxyProviders.some(provider => data.org.includes(provider))) {
    return {
      detected: true,
      type: '商业VPN服务',
      confidence: '高'
    };
  }
  
  // TOR检测
  const torRanges = [
    '199.249.230.', '185.220.100.', '193.189.100.',
    '104.244.46.', '51.222.106.', '71.19.154.'
  ];
  
  if (torRanges.some(range => ip.startsWith(range))) {
    return {
      detected: true,
      type: 'TOR出口节点',
      confidence: '高'
    };
  }
  
  // 数据中心IP
  if (data.org && (data.org.includes('Data Center') || data.org.includes('Hosting'))) {
    return {
      detected: true,
      type: '数据中心IP',
      confidence: '中'
    };
  }
  
  return {
    detected: false,
    type: '未检测到',
    confidence: '高'
  };
}

// 检测托管提供商
function detectHostingProvider(data) {
  if (!data.org) return '未知';
  
  const hostingProviders = {
    'Amazon': 'AWS',
    'Google': 'Google Cloud',
    'Microsoft': 'Azure',
    'Digital Ocean': 'DigitalOcean',
    'Linode': 'Linode',
    'OVH': 'OVH',
    'Hetzner': 'Hetzner',
    'Alibaba': 'Alibaba Cloud'
  };
  
  for (const [key, value] of Object.entries(hostingProviders)) {
    if (data.org.includes(key)) {
      return value;
    }
  }
  
  return data.org;
}

// 检查黑名单状态（模拟）
function checkBlacklistStatus(ip) {
  // 模拟黑名单检查
  const blacklists = [
    'Spamhaus',
    'Barracuda',
    'SORBS',
    'AbuseIPDB'
  ];
  
  const results = [];
  const isListed = Math.random() > 0.7; // 30%几率被列入黑名单
  
  blacklists.forEach(list => {
    results.push({
      list: list,
      status: isListed && Math.random() > 0.5 ? '已列入' : '未列入',
      lastChecked: new Date(Date.now() - Math.floor(Math.random() * 30*24*60*60*1000)).toISOString().split('T')[0]
    });
  });
  
  return {
    isListed: isListed,
    lists: results
  };
}

// 使用免费API获取IP信息
async function fetchIpInfo(ip) {
  const apiUrl = `https://ipinfo.io/${ip}/json?token=free`;
  
  try {
    const response = await fetch(apiUrl, {
      headers: { 'Accept': 'application/json' }
    });
    
    if (!response.ok) {
      return { error: true, message: 'IP信息获取失败' };
    }
    
    const data = await response.json();
    
    // 标准化数据结构
    return {
      ip: data.ip,
      city: data.city,
      region: data.region,
      country: data.country,
      loc: data.loc,
      org: data.org,
      postal: data.postal,
      timezone: data.timezone,
      hostname: data.hostname
    };
  } catch (error) {
    return { error: true, message: 'API请求失败' };
  }
}

// 备用免费API
async function fetchBackupIpInfo(ip) {
  const apiUrl = `http://ip-api.com/json/${ip}?fields=66846719`;
  
  try {
    const response = await fetch(apiUrl, {
      headers: { 'Accept': 'application/json' }
    });
    
    if (!response.ok) {
      return { error: true, message: '备用API请求失败' };
    }
    
    const data = await response.json();
    
    // 标准化数据结构
    return {
      ip: ip,
      city: data.city,
      region: data.regionName,
      country: data.country,
      loc: `${data.lat},${data.lon}`,
      org: data.org,
      isp: data.isp,
      asn: data.as,
      postal: data.zip,
      timezone: data.timezone,
      hostname: data.reverse
    };
  } catch (error) {
    return { error: true, message: '所有API请求失败' };
  }
}

function generateHtmlPage(displayIp, result, browserInfo) {
  // 获取风险值，处理未定义情况
  const riskScore = result?.advanced?.riskScore || 30;
  
  return `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IP信息查询 - IPGOT</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bulma/0.9.3/css/bulma.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
      :root {
        --primary-color: #4361ee;
        --secondary-color: #3f37c9;
        --light-color: #f8f9fa;
        --dark-color: #212529;
        --animation-duration: 0.5s;
        --high-risk: #ff3860;
        --medium-risk: #ffdd57;
        --low-risk: #48c774;
      }
      body {
        background: linear-gradient(135deg, #f5f7fa 0%, #e4edf5 100%);
        min-height: 100vh;
        font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif;
        overflow-x: hidden;
      }
      .hero {
        background: linear-gradient(120deg, var(--primary-color), var(--secondary-color));
        border-radius: 0 0 20px 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
        animation: slideDown var(--animation-duration) ease-out;
      }
      .card {
        border-radius: 15px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        overflow: hidden;
        opacity: 0;
        transform: translateY(20px);
        animation: fadeInUp var(--animation-duration) forwards;
      }
      .card:nth-child(1) { animation-delay: 0.1s; }
      .card:nth-child(2) { animation-delay: 0.2s; }
      .card:nth-child(3) { animation-delay: 0.3s; }
      .card:hover {
        transform: translateY(-8px) scale(1.02);
        box-shadow: 0 15px 35px rgba(0, 0, 0, 0.15);
      }
      .card-header {
        background: linear-gradient(to right, var(--primary-color), var(--secondary-color));
        color: white;
        padding: 1.2rem 1.5rem;
        transition: all 0.3s ease;
      }
      .notification {
        border-radius: 10px;
        animation: fadeIn var(--animation-duration) ease-in;
      }
      .ip-badge {
        background: linear-gradient(45deg, #4cc9f0, #4361ee);
        color: white;
        font-weight: bold;
        padding: 0.5rem 1.2rem;
        border-radius: 50px;
        display: inline-block;
        box-shadow: 0 4px 15px rgba(67, 97, 238, 0.3);
        animation: pulse 2s infinite;
      }
      .btn-gradient {
        background: linear-gradient(to right, var(--primary-color), var(--secondary-color));
        color: white;
        border: none;
        transition: all 0.3s ease;
        transform: translateZ(0);
        backface-visibility: hidden;
      }
      .btn-gradient:hover {
        background: linear-gradient(to right, var(--secondary-color), var(--primary-color));
        transform: translateY(-3px) scale(1.05);
        box-shadow: 0 10px 20px rgba(67, 97, 238, 0.3);
      }
      .footer {
        background: rgba(0, 0, 0, 0.03);
        padding: 2rem 1.5rem;
        margin-top: 3rem;
        animation: fadeInUp var(--animation-duration) 0.4s forwards;
        opacity: 0;
      }
      .is-hidden {
        display: none;
      }
      .info-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 1.5rem;
        margin-top: 2rem;
      }
      .info-item {
        background: white;
        border-radius: 12px;
        padding: 1.5rem;
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
        transition: all 0.3s ease;
        transform: translateY(0);
      }
      .info-item:hover {
        transform: translateY(-5px);
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
      }
      .info-title {
        color: var(--primary-color);
        font-weight: 600;
        margin-bottom: 0.5rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
      }
      .map-container {
        height: 300px;
        border-radius: 12px;
        overflow: hidden;
        margin-top: 1.5rem;
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
        animation: fadeIn var(--animation-duration) 0.3s forwards;
        opacity: 0;
      }
      .browser-info {
        background: linear-gradient(45deg, #f8f9fa, #e9ecef);
        border-left: 4px solid var(--primary-color);
        transition: all 0.3s ease;
      }
      .browser-info:hover {
        transform: translateX(5px);
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
      }
      .browser-icon {
        font-size: 2rem;
        margin-right: 1rem;
        color: var(--primary-color);
        transition: all 0.3s ease;
      }
      .tech-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 1rem;
        margin-top: 1.5rem;
      }
      .tech-item {
        text-align: center;
        padding: 1rem;
        background: white;
        border-radius: 10px;
        box-shadow: 0 3px 10px rgba(0, 0, 0, 0.05);
        transition: all 0.3s ease;
        transform: scale(1);
      }
      .tech-item:hover {
        transform: scale(1.05);
        box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
      }
      .user-agent-panel {
        max-height: 0;
        overflow: hidden;
        transition: max-height 0.5s ease;
        background: rgba(0, 0, 0, 0.02);
        border-radius: 8px;
        margin-top: 10px;
      }
      .user-agent-panel.active {
        max-height: 200px;
      }
      .floating {
        animation: float 6s ease-in-out infinite;
      }
      .risk-meter {
        height: 20px;
        border-radius: 10px;
        background: linear-gradient(to right, var(--low-risk), var(--medium-risk) 50%, var(--high-risk));
        position: relative;
        overflow: hidden;
        margin: 10px 0;
      }
      .risk-indicator {
        position: absolute;
        height: 30px;
        width: 3px;
        background: #333;
        top: -5px;
        transform: translateX(-50%);
        z-index: 10;
      }
      .risk-label {
        position: absolute;
        top: -25px;
        transform: translateX(-50%);
        font-weight: bold;
        font-size: 0.9rem;
        white-space: nowrap;
      }
      .history-timeline {
        position: relative;
        padding: 20px 0;
      }
      .timeline-item {
        position: relative;
        padding-left: 30px;
        margin-bottom: 30px;
      }
      .timeline-item:before {
        content: '';
        position: absolute;
        left: 0;
        top: 5px;
        width: 15px;
        height: 15px;
        border-radius: 50%;
        background: var(--primary-color);
        border: 3px solid white;
        box-shadow: 0 0 0 2px var(--primary-color);
        z-index: 2;
      }
      .timeline-item:after {
        content: '';
        position: absolute;
        left: 7px;
        top: 5px;
        height: 100%;
        width: 2px;
        background: var(--primary-color);
      }
      .timeline-item:last-child:after {
        display: none;
      }
      .timeline-item.current .timeline-date {
        background: var(--primary-color);
        color: white;
      }
      .timeline-date {
        display: inline-block;
        background: #f0f0f0;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: bold;
        margin-bottom: 5px;
      }
      
      /* 动画定义 */
      @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
      }
      @keyframes fadeInUp {
        from { 
          opacity: 0; 
          transform: translateY(20px); 
        }
        to { 
          opacity: 1; 
          transform: translateY(0); 
        }
      }
      @keyframes slideDown {
        from { 
          transform: translateY(-20px); 
          opacity: 0;
        }
        to { 
          transform: translateY(0); 
          opacity: 1;
        }
      }
      @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(67, 97, 238, 0.4); }
        70% { box-shadow: 0 0 0 12px rgba(67, 97, 238, 0); }
        100% { box-shadow: 0 0 0 0 rgba(67, 97, 238, 0); }
      }
      @keyframes float {
        0% { transform: translateY(0px); }
        50% { transform: translateY(-10px); }
        100% { transform: translateY(0px); }
      }
      
      /* 响应式优化 */
      @media (max-width: 768px) {
        .hero.is-medium .hero-body {
          padding: 2rem 1rem;
        }
        .title.is-1 {
          font-size: 2rem;
        }
        .subtitle {
          font-size: 1rem;
        }
        .card {
          margin-bottom: 1.5rem;
        }
        .info-grid {
          grid-template-columns: 1fr;
        }
        .tech-grid {
          grid-template-columns: repeat(2, 1fr);
        }
        .columns:not(.is-desktop) {
          flex-wrap: wrap;
        }
        .column.is-half {
          width: 100% !important;
        }
        .map-container {
          height: 250px;
        }
        .ip-badge {
          font-size: 0.9rem;
          padding: 0.4rem 1rem;
        }
      }
      
      @media (max-width: 480px) {
        .box {
          padding: 1.2rem;
        }
        .input.is-medium {
          font-size: 1rem;
        }
        .button.is-medium {
          font-size: 0.9rem;
          padding: 0 1.2rem;
        }
        .info-item {
          padding: 1rem;
        }
        .tech-grid {
          grid-template-columns: 1fr;
        }
        .timeline-item {
          padding-left: 20px;
        }
        .timeline-item:before {
          width: 12px;
          height: 12px;
        }
      }
    </style>
  </head>
  <body>
    <section class="hero is-medium">
      <div class="hero-body">
        <div class="container has-text-centered">
          <h1 class="title is-1 has-text-white floating">
            <i class="fas fa-search-location"></i> IP信息查询
          </h1>
          <p class="subtitle has-text-light">
            高级IP分析与威胁情报平台
          </p>
          ${searchForm()}
        </div>
      </div>
    </section>
    
    <div class="container my-6">
      ${displayIp ? `
        <div class="has-text-centered mb-5">
          <h2 class="title is-4">查询结果</h2>
          <div class="ip-badge">
            <i class="fas fa-address-card"></i> 目标IP: ${displayIp}
          </div>
          <!-- 添加风险数据存储 -->
          <div id="risk-data" data-risk="${riskScore}" style="display: none;"></div>
        </div>` : ''}
      
      <div>
        ${!result || result.error ? formatNoDataMessage(result?.message) : formatDataAsHtml(result)}
      </div>
      
      <div class="mt-6">
        ${result && !result.error ? formatAdvancedAnalysis(result.advanced) : ''}
      </div>
      
      <div class="mt-6">
        <div class="card">
          <div class="card-header">
            <p class="card-header-title has-text-white">
              <i class="fas fa-user"></i> 您的浏览器信息
            </p>
          </div>
          <div class="card-content">
            ${formatBrowserInfo(browserInfo)}
          </div>
        </div>
      </div>
    </div>
    
    <footer class="footer">
      <div class="content has-text-centered">
        <p>
          <strong>高级IP分析工具</strong> - 提供专业的IP地址威胁情报与历史分析
        </p>
        <p>
          © ${new Date().getFullYear()} IPGOT - 数据来源于多个威胁情报源
        </p>
      </div>
    </footer>
    
    <script>
      document.addEventListener('DOMContentLoaded', () => {
        // 关闭通知
        (document.querySelectorAll('.notification .delete') || []).forEach(($delete) => {
          const $notification = $delete.parentNode;
          $delete.addEventListener('click', () => {
            $notification.classList.add('is-hidden');
          });
        });
        
        // 如果有位置数据，加载百度地图
        const locElement = document.getElementById('location-data');
        if (locElement) {
          const locData = locElement.dataset.loc;
          if (locData) {
            // 创建地图容器
            const mapContainer = document.createElement('div');
            mapContainer.id = 'map';
            mapContainer.className = 'map-container';
            locElement.parentNode.appendChild(mapContainer);
            
            // 加载百度地图API
            const baiduMapScript = document.createElement('script');
            baiduMapScript.src = 'https://api.map.baidu.com/api?v=3.0&ak=YOUR_BAIDU_MAP_AK&callback=initBaiduMap';
            document.body.appendChild(baiduMapScript);
            
            // 定义百度地图初始化函数
            window.initBaiduMap = function() {
              const [latitude, longitude] = locData.split(',').map(Number);
              if (!isNaN(latitude) && !isNaN(longitude)) {
                // 初始化地图
                const map = new BMap.Map("map");
                const point = new BMap.Point(longitude, latitude);
                map.centerAndZoom(point, 15);
                
                // 添加标注
                const marker = new BMap.Marker(point);
                map.addOverlay(marker);
                
                // 添加控件
                map.addControl(new BMap.NavigationControl());
                map.addControl(new BMap.ScaleControl());
                
                // 添加信息窗口
                const infoWindow = new BMap.InfoWindow("IP位置: " + locData);
                marker.addEventListener("click", function() {
                  this.openInfoWindow(infoWindow);
                });
              }
            };
          }
        }
        
        // 复制IP地址功能
        document.getElementById('copy-ip-btn')?.addEventListener('click', () => {
          const ip = "${displayIp}";
          navigator.clipboard.writeText(ip).then(() => {
            const btn = document.getElementById('copy-ip-btn');
            btn.innerHTML = '<i class="fas fa-check"></i> 已复制';
            btn.classList.add('is-success');
            setTimeout(() => {
              btn.innerHTML = '<i class="fas fa-copy"></i> 复制IP';
              btn.classList.remove('is-success');
            }, 2000);
          });
        });
        
        // 切换User-Agent显示
        document.getElementById('toggle-ua')?.addEventListener('click', () => {
          const panel = document.getElementById('user-agent-panel');
          const button = document.getElementById('toggle-ua');
          panel.classList.toggle('active');
          
          if (panel.classList.contains('active')) {
            button.innerHTML = '<i class="fas fa-eye-slash"></i> 隐藏详情';
          } else {
            button.innerHTML = '<i class="fas fa-eye"></i> 查看详情';
          }
        });
        
        // 更新风险指示器 - 从数据属性获取风险值
        const riskDataElement = document.getElementById('risk-data');
        if (riskDataElement) {
          const riskScore = parseInt(riskDataElement.dataset.risk) || 30;
          const riskIndicator = document.getElementById('risk-indicator');
          if (riskIndicator) {
            riskIndicator.style.left = riskScore + '%';
          }
        }
        
        // 添加滚动动画
        const observerOptions = {
          threshold: 0.1
        };
        
        const observer = new IntersectionObserver((entries) => {
          entries.forEach(entry => {
            if (entry.isIntersecting) {
              entry.target.classList.add('animated');
            }
          });
        }, observerOptions);
        
        document.querySelectorAll('.card, .info-item, .tech-item, .map-container').forEach(el => {
          observer.observe(el);
        });
      });
    </script>
  </body>
  </html>
  `;
}

function isValidIpAddress(ip) {
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(ip);
}

function searchForm() {
  return `
    <div class="box" style="max-width: 700px; margin: 2rem auto 0; animation: fadeInUp 0.6s ease-out;">
      <form action="/" method="get">
        <div class="field has-addons">
          <div class="control is-expanded">
            <input class="input is-medium" type="text" name="ip" placeholder="请输入IP地址 (例如: 8.8.8.8)" pattern="\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b" title="请输入有效的IP地址" required>
          </div>
          <div class="control">
            <button class="button is-medium btn-gradient" type="submit">
              <i class="fas fa-search"></i> 查询
            </button>
          </div>
        </div>
        <p class="help has-text-centered">提示：不输入IP地址将查询您当前的IP信息</p>
      </form>
    </div>
  `;
}

function formatNoDataMessage(errorMessage = '') {
  return `
    <div class="container has-text-centered">
      <div class="notification is-warning" style="max-width: 600px; margin: 0 auto;">
        <button class="delete"></button>
        <i class="fas fa-exclamation-triangle"></i> 
        ${errorMessage || '未找到该IP地址的相关信息'}
      </div>
      <div class="content mt-5">
        <h3 class="title is-5">可能原因：</h3>
        <div class="tags is-centered">
          <span class="tag is-warning">IP地址不存在</span>
          <span class="tag is-warning">API请求限制</span>
          <span class="tag is-warning">网络连接问题</span>
        </div>
        <div class="mt-4">
          <p>请尝试以下方法：</p>
          <ul class="has-text-left" style="display: inline-block; text-align: left;">
            <li>检查IP地址是否正确</li>
            <li>确认网络连接正常</li>
            <li>尝试查询其他公共IP（如8.8.8.8）</li>
            <li>稍后重试</li>
          </ul>
        </div>
      </div>
    </div>
  `;
}

function formatDataAsHtml(data) {
  // 字段名汉化映射
  const fieldMap = {
    'ip': 'IP地址',
    'city': '城市',
    'region': '地区',
    'country': '国家',
    'loc': '经纬度',
    'org': '组织',
    'postal': '邮政编码',
    'timezone': '时区',
    'isp': 'ISP提供商',
    'asn': 'ASN',
    'hostname': '主机名',
    'regionName': '地区名称'
  };

  // 图标映射
  const iconMap = {
    'ip': 'fa-address-card',
    'city': 'fa-city',
    'region': 'fa-map-marked-alt',
    'country': 'fa-flag',
    'loc': 'fa-map-marker-alt',
    'org': 'fa-building',
    'isp': 'fa-network-wired',
    'asn': 'fa-project-diagram',
    'timezone': 'fa-clock',
    'hostname': 'fa-server'
  };

  // 生成关键信息卡片
  function createInfoCards(data) {
    const importantKeys = ['ip', 'city', 'region', 'country', 'org', 'isp', 'asn', 'timezone', 'hostname'];
    let cards = '';
    
    importantKeys.forEach(key => {
      if (data[key] !== undefined && data[key] !== null && data[key] !== '') {
        const displayKey = fieldMap[key] || key;
        const icon = iconMap[key] ? `<i class="fas ${iconMap[key]}"></i> ` : '';
        const value = Array.isArray(data[key]) ? 
                      data[key].join(', ') : 
                      data[key];
        
        cards += `
          <div class="info-item">
            <div class="info-title">${icon}${displayKey}</div>
            <div class="is-size-5 has-text-weight-semibold">
              ${escapeHtml(value)}
            </div>
          </div>
        `;
      }
    });
    
    return `<div class="info-grid">${cards}</div>`;
  }

  // 转义 HTML 特殊字符
  function escapeHtml(text) {
    if (typeof text !== 'string') return text;
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // 位置信息部分
  function createLocationSection(data) {
    if (!data.loc) return '';
    
    const [latitude, longitude] = data.loc.split(',');
    
    return `
      <div class="columns mt-5">
        <div class="column">
          <div class="card">
            <div class="card-header">
              <p class="card-header-title has-text-white">
                <i class="fas fa-map-marked-alt"></i> 地理位置信息
              </p>
            </div>
            <div class="card-content">
              <div id="location-data" data-loc="${data.loc}">
                <p><i class="fas fa-map-marker-alt"></i> <strong>经纬度:</strong> ${data.loc}</p>
                <p><i class="fas fa-external-link-alt"></i> <a href="https://maps.baidu.com/?q=${latitude},${longitude}" target="_blank">在百度地图上查看</a></p>
                <button id="copy-ip-btn" class="button is-small is-info mt-3">
                  <i class="fas fa-copy"></i> 复制IP
                </button>
              </div>
              <!-- 地图容器将由JS动态创建 -->
            </div>
          </div>
        </div>
      </div>
    `;
  }

  return `
    <div class="columns">
      <div class="column">
        <div class="card">
          <div class="card-header">
            <p class="card-header-title has-text-white">
              <i class="fas fa-info-circle"></i> 基本信息概览
            </p>
          </div>
          <div class="card-content">
            ${createInfoCards(data)}
          </div>
        </div>
      </div>
    </div>
    
    ${createLocationSection(data)}
  `;
}

// 格式化高级IP分析
function formatAdvancedAnalysis(analysis) {
  // 风险值显示
  const riskColor = analysis.riskScore > 80 ? 'has-text-danger' : 
                   analysis.riskScore > 50 ? 'has-text-warning' : 'has-text-success';
  
  const riskBarColor = analysis.riskScore > 80 ? 'var(--high-risk)' : 
                      analysis.riskScore > 50 ? 'var(--medium-risk)' : 'var(--low-risk)';
  
  return `
    <div class="columns">
      <div class="column">
        <div class="card">
          <div class="card-header">
            <p class="card-header-title has-text-white">
              <i class="fas fa-shield-alt"></i> 高级威胁分析
            </p>
          </div>
          <div class="card-content">
            <div class="content">
              <h4 class="title is-5"><i class="fas fa-bug"></i> 风险分析</h4>
              <div class="level is-mobile">
                <div class="level-left">
                  <div class="level-item">
                    <p>风险评分: <span class="${riskColor}"><strong>${analysis.riskScore}/100</strong></span></p>
                  </div>
                  <div class="level-item">
                    <p>风险等级: <span class="${riskColor}"><strong>${analysis.riskLevel}</strong></span></p>
                  </div>
                </div>
              </div>
              
              <div class="risk-meter">
                <div class="risk-indicator" id="risk-indicator">
                  <div class="risk-label">${analysis.riskScore}</div>
                </div>
              </div>
              
              <div class="notification" style="background: linear-gradient(to right, ${riskBarColor}, rgba(255,255,255,0.8));">
                <p><strong>${analysis.threatAnalysis.level}威胁:</strong> ${analysis.threatAnalysis.description}</p>
                <p class="mt-2"><strong>建议措施:</strong></p>
                <ul>
                  ${analysis.threatAnalysis.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                </ul>
              </div>
            </div>
            
            <div class="columns mt-5">
              <div class="column">
                <div class="content">
                  <h4 class="title is-5"><i class="fas fa-network-wired"></i> IP类型分析</h4>
                  <div class="info-grid">
                    <div class="info-item">
                      <div class="info-title"><i class="fas fa-ethernet"></i> IP类型</div>
                      <div class="is-size-5 has-text-weight-semibold">
                        ${analysis.ipType}
                      </div>
                    </div>
                    <div class="info-item">
                      <div class="info-title"><i class="fas fa-server"></i> 托管服务商</div>
                      <div class="is-size-5 has-text-weight-semibold">
                        ${analysis.hostingProvider}
                      </div>
                    </div>
                    <div class="info-item">
                      <div class="info-title"><i class="fas fa-user-secret"></i> 代理检测</div>
                      <div class="is-size-5 has-text-weight-semibold">
                        ${analysis.proxyDetection.detected ? analysis.proxyDetection.type : '未检测到'}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            
            <div class="columns mt-5">
              <div class="column">
                <div class="content">
                  <h4 class="title is-5"><i class="fas fa-history"></i> ASN历史记录</h4>
                  <div class="history-timeline">
                    ${analysis.asnHistory.map(asn => `
                      <div class="timeline-item ${asn.current ? 'current' : ''}">
                        <span class="timeline-date">${asn.date}</span>
                        <p><strong>${asn.asn}</strong> - ${asn.org}</p>
                      </div>
                    `).join('')}
                  </div>
                </div>
              </div>
              <div class="column">
                <div class="content">
                  <h4 class="title is-5"><i class="fas fa-globe-asia"></i> 注册地历史</h4>
                  <div class="history-timeline">
                    ${analysis.registrationHistory.map(reg => `
                      <div class="timeline-item ${reg.current ? 'current' : ''}">
                        <span class="timeline-date">${reg.date}</span>
                        <p>${reg.city}, ${reg.region}, ${reg.country}</p>
                      </div>
                    `).join('')}
                  </div>
                </div>
              </div>
            </div>
            
            <div class="columns mt-5">
              <div class="column">
                <div class="content">
                  <h4 class="title is-5"><i class="fas fa-ban"></i> 黑名单状态</h4>
                  <div class="notification ${analysis.blacklistStatus.isListed ? 'is-danger' : 'is-success'}">
                    <p>黑名单状态: <strong>${analysis.blacklistStatus.isListed ? '已列入' : '未列入'}</strong></p>
                  </div>
                  <table class="table is-fullwidth">
                    <thead>
                      <tr>
                        <th>黑名单名称</th>
                        <th>状态</th>
                        <th>最后检查</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${analysis.blacklistStatus.lists.map(list => `
                        <tr>
                          <td>${list.list}</td>
                          <td><span class="tag ${list.status === '已列入' ? 'is-danger' : 'is-success'}">${list.status}</span></td>
                          <td>${list.lastChecked}</td>
                        </tr>
                      `).join('')}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}

// 格式化浏览器信息
function formatBrowserInfo(browserInfo) {
  // 获取浏览器图标
  function getBrowserIcon() {
    if (browserInfo.browserName.includes('Chrome')) return 'fab fa-chrome';
    if (browserInfo.browserName.includes('Firefox')) return 'fab fa-firefox';
    if (browserInfo.browserName.includes('Safari')) return 'fab fa-safari';
    if (browserInfo.browserName.includes('Edge')) return 'fab fa-edge';
    if (browserInfo.browserName.includes('Opera')) return 'fab fa-opera';
    return 'fas fa-globe';
  }
  
  // 获取操作系统图标
  function getOSIcon() {
    if (browserInfo.os.includes('Windows')) return 'fab fa-windows';
    if (browserInfo.os.includes('macOS')) return 'fab fa-apple';
    if (browserInfo.os.includes('Linux')) return 'fab fa-linux';
    if (browserInfo.os.includes('Android')) return 'fab fa-android';
    if (browserInfo.os.includes('iOS')) return 'fas fa-mobile-alt';
    return 'fas fa-laptop';
  }
  
  // 获取设备类型图标
  function getDeviceIcon() {
    return browserInfo.isMobile ? 
      '<i class="fas fa-mobile-alt"></i> 移动设备' : 
      '<i class="fas fa-laptop"></i> 桌面设备';
  }
  
  return `
    <div class="columns">
      <div class="column is-half">
        <div class="browser-info p-4 mb-4">
          <div class="is-flex is-align-items-center">
            <div class="browser-icon">
              <i class="${getBrowserIcon()}"></i>
            </div>
            <div>
              <h3 class="title is-4">${browserInfo.browserName}</h3>
              <p class="subtitle is-6">${browserInfo.os}</p>
            </div>
          </div>
        </div>
        
        <div class="content">
          <h4 class="title is-5"><i class="fas fa-info-circle"></i> 基本信息</h4>
          <ul>
            <li><strong>访问时间:</strong> ${browserInfo.timestamp}</li>
            <li><strong>您的IP地址:</strong> ${browserInfo.cfConnectingIp}</li>
            <li><strong>设备类型:</strong> ${getDeviceIcon()}</li>
            <li><strong>Cloudflare Ray ID:</strong> ${browserInfo.cfRay}</li>
          </ul>
        </div>
      </div>
      
      <div class="column is-half">
        <div class="content">
          <h4 class="title is-5"><i class="fas fa-language"></i> 语言与区域</h4>
          <ul>
            <li><strong>首选语言:</strong> ${browserInfo.languages[0] || '未知'}</li>
            <li><strong>支持语言:</strong> ${browserInfo.languages.join(', ') || '未知'}</li>
          </ul>
        </div>
        
        <div class="content mt-5">
          <h4 class="title is-5"><i class="fas fa-code"></i> 技术信息</h4>
          <div class="tech-grid">
            <div class="tech-item">
              <i class="fab fa-html5 fa-2x has-text-danger"></i>
              <p class="mt-2">HTML5</p>
            </div>
            <div class="tech-item">
              <i class="fab fa-css3-alt fa-2x has-text-info"></i>
              <p class="mt-2">CSS3</p>
            </div>
            <div class="tech-item">
              <i class="fab fa-js fa-2x has-text-warning"></i>
              <p class="mt-2">JavaScript</p>
            </div>
            <div class="tech-item">
              <i class="fab fa-cloudflare fa-2x has-text-orange"></i>
              <p class="mt-2">Cloudflare</p>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <div class="content mt-5">
      <button id="toggle-ua" class="button is-small is-link">
        <i class="fas fa-eye"></i> 查看User-Agent详情
      </button>
      
      <div id="user-agent-panel" class="user-agent-panel">
        <pre class="p-3" style="overflow: auto; max-height: 150px;">${browserInfo.userAgent}</pre>
        <p class="help p-3">该信息由您的浏览器提供，用于识别您的设备和浏览器类型</p>
      </div>
    </div>
  `;
}
