# Apiauth
#### 介绍

Apiauth是解决客户端和服务端数据交换过程中数据加密传输处理

#### 主流程 
客户端报文：
1、请求参数键值对   （必须携带一个时间戳timestamp）
2、转化成json字符串报文
3、报文加密：openssl AES
4、报文编码（base64/bin2hex）
5、签名生成 sign
6、header 至少包含 appid apptime sign
7、请求报文传输 ：POST Content-Type： application/json,GET 请求参数为body=报文

服务端验证
1、header头参数获取，appid 查询处理签名秘钥，数据解密参数
2、报文获取，签名验证
3、报文解码，报文解密 得到请求参数
4、业务逻辑，响应参数
5、将响应参数进行加密 响应给客户端（响应不需要签名了）


#### 安装教程

composer require welld1990/apiauth 


#### demo

源码比较简单
感兴趣的可以直接看源码使用
后面我会制作一个应用案例，

#### 作者

welld1990 
QQ/邮箱： 1440080220
微信：caldwell1990
