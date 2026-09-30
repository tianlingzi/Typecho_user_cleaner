<?php

namespace TypechoPlugin\TypechoUserCleaner;

use Typecho\Common;
use Typecho\Widget\Exception as WidgetException;
use Widget\ActionInterface;
use Widget\Base;
use Widget\Notice;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

/**
 * 验证 / 重发验证邮件入口
 * 访问地址：/action/tuc-user-cleaner?do=verify|resend
 */
class Action extends Base implements ActionInterface
{
    /**
     * 动作入口
     *
     * @throws WidgetException
     */
    public function action()
    {
        $do = $this->request->get('do');

        if ('verify' === $do) {
            $this->verify();
        } elseif ('resend' === $do) {
            $this->resend();
        } elseif ('batchresend' === $do) {
            $this->batchResend();
        } else {
            throw new WidgetException(_t('请求的地址不存在'), 404);
        }
    }

    /**
     * 验证链接处理
     */
    protected function verify()
    {
        $status = 'invalid';
        $token = (string) $this->request->get('token');

        if (preg_match('/^[a-f0-9]{32,128}$/i', $token)) {
            $db = $this->db;
            $row = $db->fetchRow(
                $db->select()
                    ->from(Plugin::TOKEN_TABLE)
                    ->where('token = ?', $token)
                    ->limit(1)
            );

            if (!empty($row)) {
                if ((int) $row['status'] === 1) {
                    $status = 'used';
                } elseif ((int) $row['expires'] < (int) $this->options->time) {
                    $status = 'expired';
                } else {
                    $user = $db->fetchRow(
                        $db->select('uid', 'email_verified')
                            ->from('table.users')
                            ->where('uid = ?', $row['uid'])
                            ->limit(1)
                    );

                    if (empty($user)) {
                        $status = 'nouser';
                    } else {
                        if ((int) $user['email_verified'] !== 1) {
                            $db->query(
                                $db->update('table.users')
                                    ->rows(['email_verified' => 1])
                                    ->where('uid = ?', $user['uid'])
                            );
                        }
                        $db->query(
                            $db->update(Plugin::TOKEN_TABLE)
                                ->rows(['status' => 1])
                                ->where('uid = ?', $user['uid'])
                        );
                        $status = 'ok';
                    }
                }
            }
        }

        $this->response->throwContent($this->renderPage($status));
    }

    /**
     * 已登录用户重新发送验证邮件
     */
    protected function resend()
    {
        $this->security->protect();
        $this->user->pass('subscriber');

        $uid = (int) $this->user->uid;
        $user = $this->db->fetchRow(
            $this->db->select('uid', 'mail', 'name', 'screenName', 'email_verified')
                ->from('table.users')
                ->where('uid = ?', $uid)
                ->limit(1)
        );

        if (empty($user)) {
            $this->response->goBack(null, $this->options->adminUrl);
        }

        if ((int) $user['email_verified'] === 1) {
            Notice::alloc()->set(_t('您的邮箱已经完成验证，无需重复发送。'), 'notice');
        } else {
            try {
                Plugin::issueTokenAndMail(
                    $uid,
                    (string) $user['mail'],
                    $user['screenName'] ?: $user['name']
                );
                Notice::alloc()->set(
                    _t('验证邮件已重新发送至 %s，请在有效期内点击邮件中的链接完成验证。', $user['mail']),
                    'success'
                );
            } catch (\Throwable $e) {
                error_log('[TypechoUserCleaner] resend: ' . $e->getMessage());
                Notice::alloc()->set(_t('验证邮件发送失败，请稍后重试或联系网站管理员。'), 'notice');
            }
        }

        $this->response->redirect(Common::url('profile.php', $this->options->adminUrl));
    }

    /**
     * 管理员批量重发验证邮件（插件设置页入口）
     */
    protected function batchResend()
    {
        $this->security->protect();
        $this->user->pass('administrator');

        $db = $this->db;

        // 最早注册的主用户始终视为已验证，与核心保护规则一致
        $root = $db->fetchRow(
            $db->select('uid')->from('table.users')->order('uid', 'ASC')->limit(1)
        );
        $rootUid = empty($root) ? 0 : (int) $root['uid'];

        $users = $db->fetchAll(
            $db->select('uid', 'name', 'screenName', 'mail')
                ->from('table.users')
                ->where('email_verified = ?', 0)
        );

        $targets = [];
        if (is_array($users)) {
            foreach ($users as $u) {
                if ((int) $u['uid'] === $rootUid || empty($u['mail'])) {
                    continue;
                }
                $targets[] = $u;
            }
        }

        if (empty($targets)) {
            Notice::alloc()->set(_t('没有需要重发的未验证用户。'), 'notice');
        } else {
            $success = 0;
            $failed = 0;

            foreach ($targets as $u) {
                try {
                    Plugin::issueTokenAndMail(
                        (int) $u['uid'],
                        (string) $u['mail'],
                        $u['screenName'] ?: $u['name']
                    );
                    $success++;
                } catch (\Throwable $e) {
                    $failed++;
                    error_log('[TypechoUserCleaner] batchResend uid=' . $u['uid'] . ': ' . $e->getMessage());
                }
            }

            if ($failed > 0) {
                Notice::alloc()->set(
                    _t('批量重发完成：成功 %d 位，失败 %d 位，请检查 SMTP 配置后重试。', $success, $failed),
                    'notice'
                );
            } else {
                Notice::alloc()->set(
                    _t('批量重发完成：已成功为 %d 位用户重新发送验证邮件。', $success),
                    'success'
                );
            }
        }

        $this->response->goBack(null, $this->options->adminUrl);
    }

    /**
     * 渲染验证结果页
     *
     * @param string $status
     * @return string
     */
    protected function renderPage($status)
    {
        $options = $this->options;
        $siteName = htmlspecialchars($options->title);
        $siteUrl = htmlspecialchars($options->siteUrl);
        $loginUrl = htmlspecialchars(Common::url('profile.php', $options->adminUrl));

        switch ($status) {
            case 'ok':
                $title = _t('邮箱验证成功');
                $color = '#1e7e34';
                $message = _t('恭喜，您的邮箱已成功完成验证，现在可以正常使用全部功能了。');
                break;
            case 'used':
                $title = _t('链接已使用');
                $color = '#8a6d3b';
                $message = _t('该验证链接已经被使用，您的邮箱已经处于已验证状态。');
                break;
            case 'expired':
                $title = _t('验证链接已过期');
                $color = '#b32d2e';
                $message = _t('该验证链接已超过有效时间。请登录后在个人设置页面重新发送验证邮件。');
                break;
            case 'nouser':
                $title = _t('用户不存在');
                $color = '#b32d2e';
                $message = _t('链接对应的用户账号不存在，可能已被删除。');
                break;
            default:
                $title = _t('验证链接无效');
                $color = '#b32d2e';
                $message = _t('验证链接无效，请核对邮件中的完整链接，或登录后在个人设置页面重新发送。');
                break;
        }

        $secondary = 'ok' === $status
            ? '<a class="btn" href="' . $siteUrl . '">' . _t('返回网站首页') . '</a>'
            : '<a class="btn" href="' . $loginUrl . '">' . _t('前往登录 / 个人设置') . '</a>';

        return <<<HTML
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{$title} - {$siteName}</title>
<style>
*{box-sizing:border-box;}
body{margin:0;padding:0;background:#f5f6f7;font-family:"Microsoft YaHei",Arial,sans-serif;color:#333;}
.wrap{max-width:520px;margin:80px auto;background:#fff;border-radius:8px;
box-shadow:0 2px 12px rgba(0,0,0,.08);padding:40px 36px;text-align:center;}
h1{font-size:20px;color:{$color};margin:0 0 16px;}
p{font-size:14px;line-height:1.8;margin:0 0 24px;color:#555;}
.btns a{display:inline-block;text-decoration:none;padding:9px 22px;border-radius:4px;
font-size:14px;margin:0 6px;}
.btn{border:1px solid #ccc;color:#555;background:#f8f8f8;}
.primary{background:#467b37;color:#fff;border:1px solid #467b37;}
.site{margin-top:28px;font-size:12px;color:#999;}
.site a{color:#999;text-decoration:none;}
</style>
</head>
<body>
<div class="wrap">
<h1>{$title}</h1>
<p>{$message}</p>
<div class="btns">
<a class="btn primary" href="{$loginUrl}">
HTML
            . ('ok' === $status ? _t('进入个人中心') : _t('前往登录'))
            . '</a>'
            . $secondary
            . <<<HTML
</div>
<div class="site"><a href="{$siteUrl}">{$siteName}</a></div>
</div>
</body>
</html>
HTML;
    }
}
