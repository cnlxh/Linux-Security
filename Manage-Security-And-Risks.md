```textile
作者：李晓辉

微信联系：lxh_chat

联系邮箱: 939958092@qq.com
```

# 管理安全性和风险

风险无处不在，它可能是财务损失，也可能是你所提供服务的CIA损失，我们首先不能逃避损失，风险是客观存在的，我们应该选择科学的方法去发现、评估风险，并在风险尚未发生之时，尝试规避。

对于风险管理来说，持续性是非常重要的，没有什么风险管理是一蹴而就的，我们应当就当下的基础设施具体的状况，指定一整套持续性安全风险的监控和管理措施，并定期复盘，来增加我们的安全性。

下图说明了通过持续关注潜在安全漏洞并采取主动方法来维护安全计算环境以持续管理安全风险的过程

![continuous_risk_management_lifecycle](https://gitee.com/cnlxh/Linux-Security/raw/master/images/securityrisk/continuous_risk_management_lifecycle.png)

## 持续安全性

下图说明了融合了风险管理生命周期的持续安全生命周期

![security_and_riskmanagement_lifecycle](https://gitee.com/cnlxh/Linux-Security/raw/master/images/securityrisk/security_and_riskmanagement_lifecycle.png)

安全必须主被动兼顾。 必须在应用和基础架构生命周期的每个阶段加以考虑。

**设计** 制定安全要求，设计安全流程和规程，在设计阶段要设计后续需遵守的各项安全策略

**构建** 将安全性的策略落地，实施到我们的应用和基础架构中，在部署新系统之前，应定义好各种安全配置集合，并在事后进行自动化安全测试

**运行** 应确保将应用运行在内置安全功能的可信平台上运行，例如操作系统上个各种安全功能，ACL、SELINUX等

**管理** 监控现有基础架构和应用的使用情况以及安全趋势，并提供对应的管理界面，统一进行访问和情况展示

**灵活应变** 安全策略并不是设定好了就一尘不变，要根据环境变化来进行分析并作出相应的适应性变化，来积极发现发现新的安全问题并加以修复。

## 红帽如何帮我们管理安全性

使用最新的安全补丁更新操作系统是不够的，操作系统提供商必须吏加积极主动地解决安全问题，红帽除了提供常规的调查和跟踪之外，还将通过以下流程来传达有关安全事件对我们造成影响的准确信息

![security_risk_awareness_workflow](https://gitee.com/cnlxh/Linux-Security/raw/master/images/securityrisk/security_risk_awareness_workflow.png)

## 红帽安全严重等级

红帽产品安全团队利用低等、中等、重要及严重来划分安全等级，以及通用漏洞评估系统(CVSS)基础评分对红帽产品中发现的安全问题产生的影响进行了分级

|影响|描述|
|-|-|
|严重|该级别是针对易被未授权的远程攻击者入侵并会削弱系统功能（比如任意执行代码）却不会要求用户响应的缺陷<br>这些类型的漏洞可能会遭受蠕虫病毒的入侵。如果缺陷需要利用经过身份验证的远程用户、 本地用户或不太可能的配置，则这些缺陷不属于有严重影响的类别|
|重要|该级别是针对易于削弱资源的机密性、完整性或可用性的缺陷<br>这些类型的漏洞会让本地用户获得特权，让未经授权的远程用户查看本应受到身份验证保护的资源，让经过身份验证的远程用户执行任意代码，或让远程用户拒绝服务|
|中等|该级别是针对难以入侵但在某些情况下会部分削弱资源的机密性完整性或可用性的缺陷<br>根据对缺陷的技术评估，这些类型的漏洞具有严重的或重要的影晌，但不易遭受入侵，或者会影响不太可能遭受入侵的配置|
|低等|该级别是针对有一定安全影响的所有其他问题<br>这些类型的淜洞只在不太可能的情况下才会遭受入侵，或者即使成功入侵也只会产生最小的后果|

## 向后移植安全修复

向后移植是指从最新版本的上游软件包中修复安全缺陷，并将该修复应用于红帽分发的旧版软件包的操作，红帽采用下列步骤来向后移植安全修复：
- 确定并将修复与任何其他更改隔离开来
- 确保修复不会引入不必要的副作用
- 将修复应用于我们以前发布的版本

## 红帽CVE和勘误表

由于向后移植， 软件包的版本不是跟踪它是否容另受到特定问题影响的最佳方式。 为了更容易跟踪特定的安全漏洞， 红帽使用常见漏洞和披露(CVE)项目， 利用标准化的数字和名称来报告和跟踪与安全相关的软件问题。

每个CVE条巨都包含—个ID号， 包括年份和唯—标识它的序列号， 用于概述问题的简短描述， 以及与漏洞相关的内容链接列表（提供有关该问题的更多信息， 或讨论特定产品是否受到影响）

社区网站上的披露和CVE兼容性程序的管理由MITRE公司负责。 CVE格式还用于由美国国家标准与技术研究院(NIST) 管理的国家漏洞数据库(NVD)

红帽在分布式软件包中发布安全修复、错误修复或功能增强后， 红帽会发布勘误表公告。 勘误表公告有三种类型：

- 红帽安全公告(RHSA)

列出的软件包已经更新， 修复了与安全相关的问题。

- 红帽错误修复公告(RHBA)

列出的软件包己更新， 修复了与安全性无关的问题。

- 红帽增强功能公告(RHEA)

列出的软件包已更新， 添加了其他增强功能， 例如新功能

## 使用YUM管理安全勘误表

要检查系统可用的安全相关吏新， 请以 root 用户身份输入以下命令

```bash
[root@xiaohui ~]# yum updateinfo --security
Updating Subscription Management repositories.
Last metadata expiration check: 0:00:07 ago on Wed 08 Mar 2023 02:11:35 PM CST.
Updates Information Summary: available
    124 Security notice(s)
          1 Critical Security notice(s)
         45 Important Security notice(s)
         70 Moderate Security notice(s)
          8 Low Security notice(s)
```

输入以下Yum命令以标识与严重安全通知特别相关的RHSA:

```bash
[root@xiaohui ~]# yum updateinfo list updates | grep Critical
RHSA-2022:4765 Critical/Sec.  firefox-91.9.1-1.el9_0.x86_64
```

输入以下Yum命令以查看RHSA详细信息:

```bash
[root@xiaohui ~]# yum updateinfo list updates | grep Critical
RHSA-2022:4765 Critical/Sec.  firefox-91.9.1-1.el9_0.x86_64
[root@xiaohui ~]# yum updateinfo RHSA-2022:4765
Updating Subscription Management repositories.
Last metadata expiration check: 0:03:19 ago on Wed 08 Mar 2023 02:11:35 PM CST.
Updates Information Summary: available
    1 Security notice(s)
        1 Critical Security notice(s)

```

输入以下Yum命令， 以及RHSA详细信息中列出的CVE代码， 以确定解决严重安全问题所需的软件包

```bash
[root@xiaohui ~]# yum updateinfo list --cve RHSA-2023:0622
```

输入以下Yum命令， 以及RHSA详细信息中列出的CVE代码， 以使用解决安全问题所需的软件包来更新系统

```bash
[root@xiaohui ~]# yum update --cve RHSA-2022:8385
Updating Subscription Management repositories.
Last metadata expiration check: 0:07:45 ago on Wed 08 Mar 2023 02:11:35 PM CST.
No security updates needed, but 550 updates available
Dependencies resolved.
Nothing to do.
Complete!
```

# 回顾建议的安全实践

系统上每增加一个软件组件都会提高系统受到某些安全漏洞影响的几率。 如果用不到该软件， 那么添加该软件会增加不必要的风险

- 手工安装系统

选择minimal install最小化安装，可降低风险

- Kickstart 安装

Kickstart会自动给我们定制化安装系统，可以在%packages部分指定环境、安装包

## 了解服务的潜在风险

网络服务可能会给Linux系统带来很多风险。 了解并熟悉常见攻击非常重要， 例如：

- 拒绝服务攻击(DoS)

拒绝服务攻击会使服务被请求充满， 并且在尝试记录并回答各个请求时呈现出系统不可使用的状态。

- 分布式拒绝服务攻击(DDoS)

与Dos攻击类似， 但DDoS使用多台受感染的计算机（通常数以千计）来指引对服务的协同攻击， 使其充满请求并使其无法使用。

- 脚本漏洞攻击

当服务器使用脚本执行服务器端橾作（例如Web服务器）时， 攻击者可以定位编写有误的脚本。 这些脚本漏洞攻击可能导致缓冲区溢出状况， 或允许攻击者更改系统上的文件。

- 缓冲区溢出攻击

侦听非特权端口（如端口1到1023)的服务必须以管理特权启动， 或者必须为它们设置CAP_NET_BIND_SERVICE功能。 当进程绑定到端口并正在侦听它时， 通常会丢弃特权或功能。如果不丢弃特权或功能， 并且应用具有可利用的缓冲区溢出，则攻击者能够以运行守护进程的用户身份获取系统访问权限。 由于存在可利用的缓冲区溢出， 因此攻击者使用自动化工具来识别具有漏洞的系统， 并且当他们获得访问权限时， 可以使用自动化的隐匿程序来保持对系统的访问。

任何网络服务都可能存在安全风险， 因此关闭未使用的服务非常重要。确定哪些网络服务可在引导时启动是不够的。 您还应确定哪些端口处于打开状态并且正在侦听。

使用 ss 实用程序列出处于侦听状态的打开端口。 －tlw选项分别显示TCP套接字、侦听套接字和原始套接字。 原始套接字用千接收内核未明确支持的类型的数据包。

```bash
[root@xiaohui ~]# ss -tlw
Netid State  Recv-Q Send-Q   Local Address:Port     Peer Address:Port Process
icmp6 UNCONN 0      0    *:ipv6-icmp           *:*
tcp   LISTEN 0      4096   0.0.0.0:mountd        0.0.0.0:*
tcp   LISTEN 0      10   127.0.0.1:domain        0.0.0.0:*
tcp   LISTEN 0      10   127.0.0.1:domain        0.0.0.0:*
tcp   LISTEN 0      10   127.0.0.1:domain        0.0.0.0:*
tcp   LISTEN 0      10   127.0.0.1:domain        0.0.0.0:*
tcp   LISTEN 0      10   127.0.0.1:domain        0.0.0.0:*
tcp   LISTEN 0      10   127.0.0.1:domain        0.0.0.0:*

```
## 配置基于SSH密钥的身份验证

通过公私钥文件而不是常规密码验证，可以提供安全性，因此， 您可以根据所持有的密钥进行验证。 这样， 您就不必在每次访问系统时键入密码， 但安全性仍能得到保证。

### 生成SSH密钥

使用 ssh-keygen 命令来生成密钥对。 这将生成私钥 ~/.ssh/id_rsa和公钥~/.ssh/id_rsa.pub，并且在密钥生成期间，还可以为使用密钥时提供额外的密码，避免了密钥文件失窃后的损失

以下生成了带有密码`lixiaohui`的公私钥

```bash
[root@xiaohui ~]# ssh-keygen -N 'lixiaohui' -f ~/.ssh/id_rsa
Generating public/private rsa key pair.
Your identification has been saved in /root/.ssh/id_rsa
Your public key has been saved in /root/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:X+Nofa4sHl1hqQ/q4y3B1pURsdYvJiYhAniotqlgvPM root@xiaohui
The key's randomart image is:
+---[RSA 3072]----+
|   o.         oo |
|  o ..        .+ |
| . .  . . .   *o.|
|..     . . . +o..|
|o o     S...B.+ .|
|.=       .+X.B . |
|+ .      .*.+ o  |
|.o       o++ o   |
|  oE     o+++..  |
+----[SHA256]-----+

```
生成 SSH 密钥后， 密钥将默认存储在您的主目录中。 私钥和公钥的权限应分别为 600 和 644

使用 ssh-copy-id 命令， 将该公钥复制到您的目标系统。 现在可以使用基于密钥的身份验证向目标系统进行身份验证

需要注意的是，我们在使用公私钥登录系统时，还需要额外输入密码，避免文件失窃后的损失

```bash
[root@xiaohui ~]# ssh-copy-id root@192.168.30.129
/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "/root/.ssh/id_rsa.pub"
The authenticity of host '192.168.30.129 (192.168.30.129)' can't be established.
ED25519 key fingerprint is SHA256:agXUQ7dhUTYxKHuIVn1pF4tPtjuEB0UPFuarnaE3mF4.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed
/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys
root@192.168.30.129's password:

Number of key(s) added: 1

Now try logging into the machine, with:   "ssh 'root@192.168.30.129'"
and check to make sure that only the key(s) you wanted were added.

[root@xiaohui ~]# ssh root@192.168.30.129
Enter passphrase for key '/root/.ssh/id_rsa':
Last login: Wed Mar  8 14:05:29 2023 from 192.168.30.1
[root@xiaohui ~]#
```

### 禁止 root 用户使用SSH进行登录

作为—种安全措施， 建议您禁止 root 用户使用 ssh 直接登录系统，下例中，是允许root通过ssh登录的，请禁止，将此参数设置为no，并重启sshd服务

```bash
[root@xiaohui ~]# grep -w 'PermitRootLogin yes' /etc/ssh/sshd_config
PermitRootLogin yes
```

### 禁止使用SSH进行密码身份验证

仅允许您的帐户通过基于SSH密钥的方式进行身份验证， 是最小化安全风险的—种方法，这个参数默认生效为yes，请取消注释并设置为no，并重启sshd服务

```bash
[root@xiaohui ~]# grep -w 'PasswordAuthentication yes' /etc/ssh/sshd_config
#PasswordAuthentication yes
```

### 使用su命令获取特权

- SU 

切换到目标用户（默认清况下为 root 用户），但提供环境与调用 SU 命令的用户相同的普通shell。

```bash
[root@xiaohui ~]# su lixiaohui
[lixiaohui@xiaohui root]$ pwd
/root
[lixiaohui@xiaohui root]$ echo $PATH
/home/lixiaohui/.local/bin:/home/lixiaohui/bin:/root/.local/bin:/root/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
[lixiaohui@xiaohui root]$
```

- su -

切换到目标用户，并根据目标用户的环境调用登录shell。登录shell会重置大多数环境变量，包括目标用户的PATH
```bash
[root@xiaohui ~]# su - lixiaohui
Last login: Wed Mar  8 15:07:52 CST 2023 on pts/2
[lixiaohui@xiaohui ~]$ pwd
/home/lixiaohui
[lixiaohui@xiaohui ~]$ echo $PATH
/home/lixiaohui/.local/bin:/home/lixiaohui/bin:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin
[lixiaohui@xiaohui ~]$
```

### 使用 sudo 命令获取特权

sudo命令提供了另一种授予用户管理访问权限的方法。 当受信任的用户在管理命令之前加上前缀sudo 时， 系统会提示他们输入自己的密码。 然后， 当他们通过身份验证时（假定允许执行此管理命令）， 就会像以root用户身份执行一样来执行这个管理命令

管理员可以允许不同的 用户根据自己的需要访问特定的命令。 使用visudo命令编辑sudo配詈文件/etc/sudoers。 要授予某入对用户帐户user 的完整管理 特权， 请键入visudo, 并将下面这—行添加到用户特权定义部分中：
```bash
user ALL=(ALL) ALL 
```
在上例中， 名为user 的用户可以从任何主机使用sudo并可执行任何命令

使用sudo -i命令切换到root用户的 登录环境 。 -i选项是--login选项的缩写。 与SU -命令类似， sudo -i 可更改到root用户的主目录， 并根据root用户的环境变量打开交互式登录shell。 最大的区别在于， 因为您在／etc/sudoers文件中有一个条目， 所以您不需要知道root密码

```bash
[lixiaohui@xiaohui ~]$ sudo -i
[sudo] password for lixiaohui:
[root@xiaohui ~]# pwd
/root
[root@xiaohui ~]# echo $PATH
/root/.local/bin:/root/bin:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
[root@xiaohui ~]#

```