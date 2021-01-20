<?php
/**
+------------------------------------------------------------------------------
* API接口数据加密传输
* --OPENSSL AES实现
+------------------------------------------------------------------------------
* @author  welld1990 <1440080220@qq.com>
* @version Id: AesClient.php  2021年1月20日 下午5:13:25
+------------------------------------------------------------------------------
*/
namespace welld1990\Apiauth;
class AesClient {
    
    /**
     * 当前请求所属的api客户端信息
     */
    private $config = array(
        //客户端ID
        'appid' => '10000',
        //签名密钥
        'secret' => '0922587b9c2a92b242e3abcede92e9c3',
        //数据解密密码
        'pwd' => 'ef111c4604ad0610',
        //解密iv
        'iv' => '9294395459492873',
        //报文编码方式 base64方式，hex2bin方式
        'decode' => 'base64',
        //可选参数-指定那些参数参与签名
        'sign_param' => ''
    );
    
    /**
     * 签名验证数据
     * @var array
     */
    private $headers = array(
        'appid' => '10153',
        'apptime' => '',
        'signature' => '',
    );
    
    /**
     * 请求原始报文
     * @var string
     */
    private $request_body = '';
    /**
     * 请求报文解密后键值对
     * @var array
     */
    private $request_parm = array();
    
    /**
     * 错误消息
     * @var string
     */
    private $error = '';
    
    /**
     * 构造方法，配置初始化
     * @param array $config 配置参数
     */
    public function __construct(array $config,array $headers) {
        /* 获取配置 */
        $this->config = array_merge($this->config, $config);
        //header头
        $this->headers = array_merge($this->headers, $headers);
    }
    
    /**
     * 请求验证入口
     * @access public
     * @return void
     */
    public function request() {
        
        //到这里还是没有客户端信息，那么返回异常
        if (!$this->config || !$this->headers)
        {
            $this->error = "无法找到对应的api客户端信息或api客户端被停用 [server]";
            return false;
        }
        
        //加密参数获取
        $this->getRequestBody();
        
        //生成签名
        $signature = $this->makeSign();
        
        //验证签名
        if (strcmp($signature, $this->headers['signature']) != 0)
        {
            $this->error = "签名错误";
            return false;
        }
        
        //解密参数和验证
        return $this->decryptParam();
        
    }
    
    /**
     * 获取参数
     */
    public function getRequestParam($name=null){
        if($name !== null){
            return $this->request_parm[$name];
        }else{
            return $this->request_parm;
        }
    }
    
    /**
     * 读取报文
     */
    private function getRequestBody(){
        //开始处理数据--post 和get
        if (strtoupper($_SERVER['REQUEST_METHOD']) == 'GET'){
            $this->request_body = $_GET['body'];
        }else{
            $this->request_body = file_get_contents("php://input");
        }
        
    }
    
    /**
     * 签名算法
     */
    public function makeSign(){
        $body = $this->request_body;
        
        //body md5
        $body= md5($body);
        
        //参数只保留前16位
        $body = substr($body,0,16);
        
        //参数 + appsecret
        $body = $body.$this->config['secret'];
        
        //参数排序
        $body = str_split($body);
        asort($body);
        $body = implode('',$body);
        
        $signature = $body.$this->headers['apptime'];
        
        //↑↑↑↑以上为固定的签名参数
        //↓↓↓↓自定义参与签名的参数
        if($this->config['sign_param']){
            $otherParam = explode(',', $this->config['sign_param']);
            foreach ($otherParam as $val){
                $signature .= $this->headers[$val];
            }
        }
        
        return md5($signature);
    }
    
    /**
     * 报文解码
     */
    private function decodeBody(){
        
        if ($this->config['decode'] == 'hex2bin'){
            return hex2bin($this->request_body);
        }
        
        if ($this->config['decode'] == 'base64'){
            //默认base64
            return base64_decode($this->request_body);
        }
        
        return false;
    }
    
    /**
     * 报文解密
     * @return boolean
     */
    private function decryptParam(){
        if (empty($this->request_body))
        {
            $this->error = "请求报文异常 ";
            return false;
        }
        
        //报文解码
        $rsabody = $this->decodeBody();
        if(!$rsabody){
            $this->error = "无法识别请求报文 ";
            return false;
        }
        
        //报文解密
        $rsabody = openssl_decrypt($rsabody, 'AES-128-CBC',$this->config['pwd'], OPENSSL_RAW_DATA,$this->config['iv']);
        if(!$rsabody){
            $this->error = '请求报文无法解析';
            return false;
        }
        
        //报文转化成键值对
        $rsabody = json_decode($rsabody,true);
        if (empty($rsabody))
        {
            $this->error = "请求报文无法解析";
            return false;
        }
        
        $this->request_parm = $rsabody;
        
        return true;
    }
    
    /**
     * 报文解码
     * @param string $body
     * @return string
     */
    private function encodeBody(string $body){
        
        if ($this->config['decode'] == 'hex2bin'){
            return bin2hex($body);
        }
        
        if ($this->config['decode'] == 'base64'){
            //默认base64
            return base64_encode($body);
        }
        
        return '';
    }
    
    /**
     * 响应内容加密
     * @param array $data
     * @return string
     */
    public function response(array $data){
        //转化成字符串
        $data = json_encode($data);
        
        //加密报文
        $data = openssl_encrypt($data, 'AES-128-CBC', $this->config['pwd'], OPENSSL_RAW_DATA,$this->config['iv']);
        
        //转码
        return $this->encodeBody($data);
    }
    
    /**
     *获取错误消息
     */
    public function getError(){
        
        return $this->error;
    }
}