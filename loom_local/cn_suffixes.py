# Host suffixes treated as mainland China. Matched as exact host or domain suffix.
# School / LAN hosts are NOT listed here; those stay DIRECT (campus).

import ipaddress

CN_SUFFIXES = (
    "cn",
    "中国",
    "公司",
    "网络",
    "baidu.com",
    "baidu.jp",
    "bdstatic.com",
    "bdimg.com",
    "baidustatic.com",
    "qq.com",
    "gtimg.com",
    "qcloud.com",
    "qpic.cn",
    "myqcloud.com",
    "tencent.com",
    "tencent-cloud.net",
    "weixin.com",
    "wechat.com",
    "weixin.qq.com",
    "taobao.com",
    "tmall.com",
    "alicdn.com",
    "aliyun.com",
    "alipay.com",
    "alipayobjects.com",
    "alibaba.com",
    "aliyuncs.com",
    "mmstat.com",
    "tbcdn.cn",
    "163.com",
    "126.com",
    "127.net",
    "netease.com",
    "youdao.com",
    "bilibili.com",
    "bilibili.cn",
    "biliapi.com",
    "biliapi.net",
    "bilivideo.com",
    "bilivideo.cn",
    "hdslb.com",
    "hdslb.net",
    "szbdyd.com",
    "biliintl.com",
    "bilicdn1.com",
    "iqiyi.com",
    "iqiyipic.com",
    "youku.com",
    "ykimg.com",
    "douyin.com",
    "douyincdn.com",
    "douyinvod.com",
    "douyinpic.com",
    "douyinstatic.com",
    "douyinliving.com",
    "bytegecko.com",
    "bytetcc.com",
    "bytescm.com",
    "ibytedtos.com",
    "bytetos.com",
    "bytecdn.cn",
    "bytegoofy.com",
    "bytevdn.com",
    "doubao.com",
    "bytedance.com",
    "byteimg.com",
    "zijieapi.com",
    "umeng.com",
    "umengcloud.com",
    "bdurl.net",
    "amemv.com",
    "feishu.cn",
    "larksuite.cn",
    "jd.com",
    "jdcdn.com",
    "360buyimg.com",
    "pinduoduo.com",
    "yangkeduo.com",
    "meituan.com",
    "meituan.net",
    "dianping.com",
    "dpfile.com",
    "ctrip.com",
    "c-ctrip.com",
    "12306.cn",
    "weibo.com",
    "weibo.cn",
    "sina.com",
    "sina.com.cn",
    "sinaimg.cn",
    "sohu.com",
    "sohucs.com",
    "zhihu.com",
    "zhimg.com",
    "xiaohongshu.com",
    "xhscdn.com",
    "douyu.com",
    "huya.com",
    "csdn.net",
    "gitee.com",
    "huawei.com",
    "hicloud.com",
    "vmall.com",
    "mi.com",
    "xiaomi.com",
    "miui.com",
    "vivo.com",
    "oppo.com",
    "oneplus.com",
    "dingtalk.com",
    "dingtalkapps.com",
    "laiwang.com",
    "smzdm.com",
    "eastmoney.com",
    "xueqiu.com",
    "douban.com",
    "doubanio.com",
    "acfun.cn",
    "kuaishou.com",
    "yximgs.com",
    "pstatp.com",
    "snssdk.com",
    "toutiao.com",
    "ixigua.com",
    "bcebos.com",
    "qiniucdn.com",
    "qiniudn.com",
    "upyun.com",
)

# Always campus / local, even if they look Chinese.
DIRECT_SUFFIXES = (
    "yungu.org",
    "yungu-inc.org",
    "yunguhs.com",
    "localhost",
)
TASK_YUNGU_IPS = ("116.62.109.80",)


def is_yungu_related(host: str) -> bool:
    """School task site and its OSS/telemetry: campus exit only, never VPS."""
    host = (host or "").lower().split("%")[0].rstrip(".")
    if not host:
        return False
    if host in TASK_YUNGU_IPS:
        return True
    return "yungu" in host


# 网易云、百度、Prometric、图寻固定走校园网。其它国内站仍可走洛杉矶。
CAMPUS_CN_SUFFIXES = (
    "tuxun.fun",
    "daai.fun",
    "chao-fan.com",
    "dbankcdn.cn",
    "prometric.com.cn",
    "music.163.com",
    "iplay.163.com",
    "look.163.com",
    "music.126.net",
    "vod.126.net",
    "baidu.com",
    "baidu.jp",
    "bdstatic.com",
    "bdimg.com",
    "baidustatic.com",
    "baidubce.com",
    "baidupcs.com",
    "hao123.com",
)

_BILI_MARKS = ("bili", "hdslb", "szbdyd", "b23.tv", "acgvideo", "acg.tv", "upos-")


def is_bilibili_related(host: str) -> bool:
    host = (host or "").lower().split("%")[0].rstrip(".")
    return any(mark in host for mark in _BILI_MARKS)


def is_public_ip_literal(host: str) -> bool:
    try:
        addr = ipaddress.ip_address((host or "").strip("[]"))
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    )


def is_campus_cn(host: str) -> bool:
    host = (host or "").lower().split("%")[0].rstrip(".")
    return any(host == s or host.endswith("." + s) for s in CAMPUS_CN_SUFFIXES)
