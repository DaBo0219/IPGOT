**<h1>IP信息查询工具 - IPGOT</h1>**

**IP信息查询工具 - IPGOT** 是一个基于Cloudflare Workers构建的高级IP信息查询工具，提供详细的IP地址分析、地理位置信息和威胁情报。

**演示站 http://www.ipgot.shop/**

<h2>🌟 功能特性</h2>

**🔍 实时IP地址信息查询**

**🗺️ 详细的地理位置信息显示**

**⚠️ 高级威胁分析和风险评估**

**🌐 浏览器信息检测**

**📅 IP历史记录分析**

**⛔ 黑名单状态检查**

**📱 响应式设计，适配各种设备**

<h2>🗺️ 两种地图版本</h2>
项目包含两个版本，分别使用不同的地图服务：

**新增版本**
应用VirusTotalAPI、ip2locationAPI、IPAPI的免费额度key增强识别精度 脚本名称V&I由百度版本变换而来所以这个版本也需要加百度的key

**1. 百度地图版本 (baidu-map-version.js)**
**优点：**

在中国大陆地区**加载速度快**

提供**详细的中文地图信息**

支持**中文地址解析**

在中国大陆地区有**更好的覆盖精度**

**缺点：**

**需要百度地图API密钥**

国际覆盖不如谷歌地图

在中国大陆以外地区**加载速度较慢**

需要额外的百度地图API调用

**2. Leaflet + OpenStreetMap版本 (leaflet-osm-version.js)**
**优点：**

**无需API密钥**

**全球覆盖均匀**

**开源且免费**

**加载速度快**（使用CDN）

**高度可定制化**

支持多种地图图层

缺点：

在中国大陆地区可能加载较慢

中文地址支持不如百度地图详细

某些地区的地图细节可能不如商业地图服务

<h2>🚀 如何部署</h2>
<h3>前提条件</h3>
<li><strong>Cloudflare账户</strong></li>

<li><strong>Cloudflare Workers服务</strong></li>

<h3>部署步骤</h3>

**1.marker>登录Cloudflare仪表板**

**2.进入Workers & Pages服务**

**3.创建新的Worker服务**

**4.复制所选版本代码粘贴到编辑器中**

**5.保存并部署**

<h3>对于百度地图版本</h3>

**需要额外配置：**

访问百度地图开放平台申请API密钥

在代码中替换以下部分：

855行

> baiduMapScript.src = 'https://api.map.baidu.com/api?v=3.0&ak=YOUR_BAIDU_MAP_AK&callback=initBaiduMap';

将YOUR_BAIDU_MAP_AK替换为您实际的百度地图API密钥

🛠️ 技术栈
<li><strong>Cloudflare Workers</strong></li>

<li><strong>HTML5/CSS3</strong></li>

<li><strong>JavaScript</strong></li>

<li><strong>Bulma CSS框架</strong></li>

<li><strong>Font Awesome图标</strong></li>

<li><strong>百度地图API 或 Leaflet.js + OpenStreetMap </strong></li>

<h2>🧩 自定义选项</h2>

您可以根据需要**自定义：**

修改CSS变量调整**主题颜色**

添加更多**威胁情报源**

集成其他**IP**信息**API**

调整**风险评估算法**

<h2>🤝 贡献指南</h2>
欢迎贡献代码！请遵循以下步骤：

**Fork**本项目

创建新分支 (git checkout -b feature/your-feature)

提交更改 (git commit -am 'Add some feature')

推送到分支 (git push origin feature/your-feature)

创建Pull Request

<h2>❓ 常见问题</h2>

**Q: 为什么有时无法获取IP信息？**
A: 可能是由于API限制或网络问题，请尝试使用备用查询服务或稍后重试。

**Q: 地图无法加载怎么办？**
A: 检查网络连接，确保地图服务在您所在地区可用。对于百度地图版本，请确认API密钥有效。

**Q: 如何提高查询精度？**
A: 您可以集成更多IP信息源或使用商业IP数据库。

<h2>👤 作者</h2>

**DaBo0219**
