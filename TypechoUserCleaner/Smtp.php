<?php

namespace TypechoPlugin\TypechoUserCleaner;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

/**
 * 轻量级 SMTP 客户端（支持 SSL 465 / STARTTLS 587 / AUTH LOGIN）
 */
class Smtp
{
    /** @var string */
    private $host;

    /** @var int */
    private $port;

    /** @var string ssl|tls|none */
    private $secure;

    /** @var string */
    private $username;

    /** @var string */
    private $password;

    /** @var int 秒 */
    private $timeout = 15;

    /** @var resource|null */
    private $fp;

    /**
     * @param string $host
     * @param int    $port
     * @param string $secure
     * @param string $username
     * @param string $password
     */
    public function __construct($host, $port = 465, $secure = 'ssl', $username = '', $password = '')
    {
        $this->host = (string) $host;
        $this->port = (int) $port;
        $this->secure = $secure;
        $this->username = (string) $username;
        $this->password = (string) $password;
    }

    /**
     * 发送一封 HTML + 纯文本备选邮件
     *
     * @param string $from
     * @param string $fromName
     * @param string $to
     * @param string $subject
     * @param string $html
     * @param string $text
     * @throws \Exception
     */
    public function send($from, $fromName, $to, $subject, $html, $text = '')
    {
        $this->connect();
        $this->expect([220]);

        $this->ehlo();

        if ('tls' === $this->secure) {
            $this->command('STARTTLS', [220]);
            if (
                !@stream_socket_enable_crypto(
                    $this->fp,
                    true,
                    [
                        'verify_peer'      => false,
                        'verify_peer_name' => false,
                        'allow_self_signed' => true,
                    ]
                )
            ) {
                throw new \Exception('STARTTLS encryption failed');
            }
            $this->ehlo();
        }

        if ('' !== $this->username) {
            $this->command('AUTH LOGIN', [334]);
            $this->command(base64_encode($this->username), [334]);
            $this->command(base64_encode($this->password), [235]);
        }

        $this->command('MAIL FROM:<' . $this->cleanAddress($from) . '>', [250]);
        $this->command('RCPT TO:<' . $this->cleanAddress($to) . '>', [250, 251]);
        $this->command('DATA', [354]);

        $boundary = 'b=_' . md5(uniqid((string) mt_rand(), true));
        $hostname = $this->hostname();

        $headers = [
            'Date: ' . date('r'),
            'From: ' . $this->formatName($fromName) . ' <' . $this->cleanAddress($from) . '>',
            'To: <' . $this->cleanAddress($to) . '>',
            'Subject: ' . $this->encodeHeader($subject),
            'Message-ID: <' . md5(uniqid((string) mt_rand(), true)) . '@' . $hostname . '>',
            'MIME-Version: 1.0',
            'X-Mailer: TypechoUserCleaner',
            'Content-Type: multipart/alternative; boundary="' . $boundary . '"',
        ];

        if ('' === $text) {
            $text = html_entity_decode(strip_tags($html), ENT_QUOTES, 'UTF-8');
        }

        $content = implode("\r\n", $headers) . "\r\n\r\n";
        $content .= '--' . $boundary . "\r\n";
        $content .= "Content-Type: text/plain; charset=UTF-8\r\n";
        $content .= "Content-Transfer-Encoding: 8bit\r\n\r\n";
        $content .= $this->dotStuff($text) . "\r\n\r\n";
        $content .= '--' . $boundary . "\r\n";
        $content .= "Content-Type: text/html; charset=UTF-8\r\n";
        $content .= "Content-Transfer-Encoding: 8bit\r\n\r\n";
        $content .= $this->dotStuff($html) . "\r\n\r\n";
        $content .= '--' . $boundary . "--\r\n";

        $this->write($content);
        $this->write("\r\n.\r\n");
        $this->expect([250]);

        $this->command('QUIT', [221], true);
        @fclose($this->fp);
        $this->fp = null;
    }

    /**
     * 建立 TCP / SSL 连接
     *
     * @throws \Exception
     */
    protected function connect()
    {
        if ('' === $this->host) {
            throw new \Exception('SMTP host is empty');
        }

        $remote = ('ssl' === $this->secure ? 'ssl://' : 'tcp://') . $this->host . ':' . $this->port;
        $errno = 0;
        $errstr = '';

        $context = stream_context_create([
            'ssl' => [
                'verify_peer'      => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true,
            ],
        ]);

        $this->fp = @stream_socket_client(
            $remote,
            $errno,
            $errstr,
            $this->timeout,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!is_resource($this->fp)) {
            throw new \Exception('Connect SMTP server failed: ' . $errstr . ' (' . $errno . ')');
        }

        stream_set_timeout($this->fp, $this->timeout);
    }

    /**
     * EHLO 握手
     *
     * @throws \Exception
     */
    private function ehlo()
    {
        $this->command('EHLO ' . $this->hostname(), [250]);
    }

    /**
     * 发送命令并校验返回码
     *
     * @param string $command
     * @param int[]  $expect
     * @param bool   $optional
     * @return string
     * @throws \Exception
     */
    private function command($command, array $expect, $optional = false)
    {
        $this->write($command . "\r\n");
        return $this->expect($expect, $optional);
    }

    /**
     * 读取服务器返回并匹配状态码
     *
     * @param int[] $expect
     * @param bool  $optional
     * @return string
     * @throws \Exception
     */
    private function expect(array $expect, $optional = false)
    {
        $response = $this->read();
        $code = (int) substr($response, 0, 3);
        if (!in_array($code, $expect, true)) {
            if ($optional) {
                return $response;
            }
            throw new \Exception('SMTP error: ' . trim($response));
        }
        return $response;
    }

    /**
     * 读取完整应答（兼容多行）
     *
     * @return string
     * @throws \Exception
     */
    private function read()
    {
        $data = '';
        $deadline = time() + $this->timeout;

        while (time() <= $deadline) {
            $line = fgets($this->fp, 515);
            if (false === $line) {
                break;
            }
            $data .= $line;
            // 应答格式："250-xxx" 为续行，"250 xxx" 为结束行
            if (strlen($line) >= 4 && ' ' === $line[3]) {
                return $data;
            }
        }

        throw new \Exception('SMTP read timeout: ' . trim($data));
    }

    /**
     * 写入全部数据
     *
     * @param string $data
     * @throws \Exception
     */
    private function write($data)
    {
        $length = strlen($data);
        $written = 0;

        while ($written < $length) {
            $n = @fwrite($this->fp, substr($data, $written));
            if (false === $n || 0 === $n) {
                throw new \Exception('SMTP write failed');
            }
            $written += $n;
        }
    }

    /**
     * DATA 内容的点号转义
     *
     * @param string $data
     * @return string
     */
    private function dotStuff($data)
    {
        $data = str_replace(["\r\n", "\r"], "\n", $data);
        $lines = explode("\n", $data);
        foreach ($lines as $i => $line) {
            if (isset($line[0]) && '.' === $line[0]) {
                $lines[$i] = '.' . $line;
            }
        }
        return implode("\r\n", $lines);
    }

    /**
     * 头部名称编码
     *
     * @param string $name
     * @return string
     */
    private function formatName($name)
    {
        $name = trim((string) $name);
        if ('' === $name) {
            return '';
        }
        return '=?UTF-8?B?' . base64_encode($name) . '?=';
    }

    /**
     * 邮件标题编码
     *
     * @param string $subject
     * @return string
     */
    private function encodeHeader($subject)
    {
        return '=?UTF-8?B?' . base64_encode((string) $subject) . '?=';
    }

    /**
     * 去除地址中可能导致协议注入的字符
     *
     * @param string $address
     * @return string
     */
    private function cleanAddress($address)
    {
        return preg_replace('/[\r\n<>]/', '', (string) $address);
    }

    /**
     * 用于 EHLO / Message-ID 的主机名
     *
     * @return string
     */
    private function hostname()
    {
        $host = !empty($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost';
        $host = preg_replace('/[^a-z0-9.\-]/i', '', $host);
        return '' === $host ? 'localhost' : $host;
    }
}
