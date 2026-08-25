// SPDX-License-Identifier: MPL-2.0
package router

// BuiltinDirectSuffixes contains high-frequency Chinese top-level domains,
// popular domestic internet companies, Apple China services, Microsoft, and utility services.
var BuiltinDirectSuffixes = []string{
	// TLDs
	"cn",
	"xn--fiqs8s", // .中国
	"xn--55qx5d", // .公司
	"xn--io0a7i", // .网络

	// Apple Services (Direct in China)
	"apple.com",
	"icloud.com",
	"icloud-content.com",
	"cdn-apple.com",
	"mzstatic.com",
	"aaplimg.com",
	"apple-cloudkit.com",
	"apple-livephotoskit.com",

	// Tencent / WeChat / QQ
	"qq.com",
	"weixin.com",
	"qpic.cn",
	"qlogo.cn",
	"tenpay.com",
	"tencent.com",
	"tencent-cloud.net",
	"gtimg.cn",
	"gtimg.com",
	"wechat.com",

	// Alibaba / Taobao / Alipay
	"taobao.com",
	"tmall.com",
	"alipay.com",
	"alipayobjects.com",
	"alibaba.com",
	"alicdn.com",
	"aliyun.com",
	"aliyuncs.com",
	"tbcdn.cn",
	"1688.com",

	// Baidu
	"baidu.com",
	"bdimg.com",
	"bdstatic.com",
	"baidupcs.com",
	"hao123.com",

	// Bilibili
	"bilibili.com",
	"hdslb.com",
	"bilivideo.com",
	"biliapi.net",

	// ByteDance / Douyin / TikTok CN
	"douyin.com",
	"bytedance.com",
	"byteimg.com",
	"douyincdn.com",
	"zjurl.cn",
	"toutiao.com",
	"feishu.cn",

	// JD
	"jd.com",
	"360buyimg.com",
	"jdpay.com",

	// NetEase
	"163.com",
	"126.net",
	"yeah.net",
	"netease.com",
	"127.net",

	// Meituan & Dianping
	"meituan.com",
	"dianping.com",
	"dpfile.com",
	"meituan.net",

	// Zhihu / Weibo / Xiaohongshu
	"zhihu.com",
	"zhimg.com",
	"weibo.com",
	"weibo.cn",
	"sinaimg.cn",
	"sina.com.cn",
	"xiaohongshu.com",
	"xhscdn.com",

	// Domestic OEM & Hardware
	"xiaomi.com",
	"mi.com",
	"mi-img.com",
	"huawei.com",
	"dbankcdn.com",
	"honor.cn",
	"honor.com",
	"oppo.com",
	"vivo.com",

	// Navigation & Map
	"amap.com",
	"autonavi.com",
	"gaode.com",

	// Domestic Banking & Payment
	"unionpay.com",
	"95516.com",
	"icbc.com.cn",
	"ccb.com",
	"boc.cn",
	"abchina.com",
	"cmbchina.com",
	"bankofchina.com",

	// Domestic Media & Music
	"kuaishou.com",
	"kuaishoupay.com",
	"youku.com",
	"iqiyi.com",
	"qiyi.cn",
	"mgtv.com",
	"ximalaya.com",
	"kugou.com",
	"kuwo.cn",
}

// BuiltinBlockSuffixes contains common high-intrusive mobile ad and telemetry trackers.
var BuiltinBlockSuffixes = []string{
	"googleads.g.doubleclick.net",
	"pagead2.googlesyndication.com",
	"adservice.google.com",
	"adcolony.com",
	"unityads.unity3d.com",
	"applovin.com",
	"vungle.com",
	"ironsrc.com",
}
