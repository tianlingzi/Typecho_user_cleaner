<?php

namespace TypechoPlugin\TypechoUserCleaner;

use Typecho\Common;
use Typecho\Db;
use Typecho\Plugin\PluginInterface;
use Typecho\Widget\Helper\Form;
use Typecho\Widget\Helper\Form\Element;
use Typecho\Widget\Helper\Form\Element\Password;
use Typecho\Widget\Helper\Form\Element\Select;
use Typecho\Widget\Helper\Form\Element\Hidden;
use Typecho\Widget\Helper\Form\Element\Text;
use Typecho\Widget\Helper\Form\Element\Textarea;
use Widget\Options;
use Widget\Security;
use Widget\User;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

/**
 * 新用户邮箱验证。
 *
 * 注册后生成一次性验证链接并通过 SMTP 发送，在有效期内完成验证后
 * email_verified 置为 1；未验证用户被管理员删除时自动发送提醒邮件。
 *
 * @package TypechoUserCleaner
 * @author tianlingzi
 * @version 1.1.0
 * @link https://www.tianlingzi.top
 */
class Plugin implements PluginInterface
{
    /** 后台 action 名称 */
    public const ACTION_NAME = 'tuc-user-cleaner';

    /** token 表（Typecho 表名占位符） */
    public const TOKEN_TABLE = 'table.user_cleaner_tokens';

    /**
     * 激活插件
     */
    public static function activate()
    {
        $db = Db::get();
        $prefix = $db->getPrefix();
        $usersTable = $prefix . 'users';
        $tokenTable = $prefix . 'user_cleaner_tokens';
        $type = self::adapterType($db);

        // users 表新增 email_verified 字段
        if (!self::columnExists($db, $usersTable, 'email_verified', $type)) {
            if ('pgsql' === $type) {
                $db->query('ALTER TABLE "' . $usersTable . '" ADD COLUMN "email_verified" SMALLINT NOT NULL DEFAULT 0');
            } else {
                $db->query('ALTER TABLE `' . $usersTable . '` ADD COLUMN `email_verified` TINYINT NOT NULL DEFAULT 0');
            }
        }

        // 启用时所有已存在的用户视为已验证
        if ('pgsql' === $type) {
            $db->query('UPDATE "' . $usersTable . '" SET "email_verified" = 1');
        } else {
            $db->query('UPDATE `' . $usersTable . '` SET `email_verified` = 1');
        }

        self::createTokenTable($db, $tokenTable, $type);
        self::updateActionTable(true);

        \Typecho\Plugin::factory('Widget\Register')->finishRegister = __CLASS__ . '::onFinishRegister';
        \Typecho\Plugin::factory('admin/footer.php')->begin = __CLASS__ . '::adminFooter';

        return _t('插件已启用：现有用户已全部标记为已验证，此后新注册的用户需要完成邮箱验证。');
    }

    /**
     * 禁用插件
     */
    public static function deactivate()
    {
        $db = Db::get();
        $prefix = $db->getPrefix();
        $type = self::adapterType($db);

        self::updateActionTable(false);

        // 删除 token 表
        if ('pgsql' === $type) {
            $db->query('DROP TABLE IF EXISTS "' . $prefix . 'user_cleaner_tokens"');
            $db->query('ALTER TABLE "' . $prefix . 'users" DROP COLUMN "email_verified"');
        } elseif ('sqlite' === $type) {
            $db->query('DROP TABLE IF EXISTS "' . $prefix . 'user_cleaner_tokens"');
            // SQLite 旧版本不支持 DROP COLUMN，保留该字段不影响系统运行
        } else {
            $db->query('DROP TABLE IF EXISTS `' . $prefix . 'user_cleaner_tokens`');
            $db->query('ALTER TABLE `' . $prefix . 'users` DROP COLUMN `email_verified`');
        }
    }

    /**
     * 插件配置面板
     *
     * @param Form $form
     */
    public static function config(Form $form)
    {
        $host = new Text('host', null, null, _t('SMTP 服务器地址'), _t('例如 smtp.qq.com、smtp.163.com、smtp.feishu.cn'));
        $form->addInput($host);

        $port = new Text('port', null, '465', _t('SMTP 端口'), _t('SSL 一般为 465，TLS 一般为 587，不加密一般为 25'));
        $form->addInput($port);

        $secure = new Select(
            'secure',
            [
                'ssl'  => _t('SSL（推荐，端口 465）'),
                'tls'  => _t('TLS（端口 587）'),
                'none' => _t('不加密（端口 25）'),
            ],
            'ssl',
            _t('加密方式')
        );
        $form->addInput($secure);

        $username = new Text('username', null, null, _t('SMTP 用户名'), _t('通常与发件邮箱一致'));
        $form->addInput($username);

        $password = new Password('password', null, null, _t('SMTP 密码 / 授权码'), _t('QQ邮箱、163邮箱等请填写“授权码”而不是登录密码'));
        $form->addInput($password);

        $from = new Text('from', null, null, _t('发件邮箱地址'), _t('留空则使用 SMTP 用户名'));
        $form->addInput($from);

        $fromName = new Text('fromName', null, null, _t('发件人名称'), _t('留空则使用网站名称'));
        $form->addInput($fromName);

        $expire = new Text('expire', null, '24', _t('验证链接有效时间（小时）'), _t('默认 24 小时，请填写正整数'));
        $form->addInput($expire);

        $subject = new Text(
            'subject',
            null,
            '【{sitename}】请完成邮箱验证',
            _t('验证邮件标题'),
            _t('可用变量：{sitename} {username} {expire}')
        );
        $form->addInput($subject);

        $body = new Textarea(
            'body',
            null,
            self::defaultBody(),
            _t('验证邮件正文（HTML）'),
            _t('可用变量：{sitename} {username} {link} {expire}')
        );
        $body->input->setAttribute('class', 'w-90');
        $body->input->setAttribute('rows', '10');
        $form->addInput($body);
    }

    /**
     * 个人设置面板：邮箱验证状态
     *
     * @param Form $form
     */
    public static function personalConfig(Form $form)
    {
        $user = User::alloc();
        if (!$user->hasLogin()) {
            return;
        }

        $db = Db::get();
        $row = $db->fetchRow(
            $db->select('mail', 'screenName', 'email_verified')
                ->from('table.users')
                ->where('uid = ?', $user->uid)
                ->limit(1)
        );

        if (empty($row)) {
            return;
        }

        $verified = (int) $row['email_verified'] === 1;
        if ($verified) {
            $html = '<p><span style="display:inline-block;padding:2px 10px;border-radius:3px;'
                . 'background:#e6f4ea;color:#1e7e34;border:1px solid #b7dfc1;">'
                . _t('邮箱已验证') . '</span></p>'
                . '<p class="description">' . htmlspecialchars($row['mail']) . '</p>';
        } else {
            $expiresText = '';
            $token = $db->fetchRow(
                $db->select('expires')
                    ->from(self::TOKEN_TABLE)
                    ->where('uid = ?', $user->uid)
                    ->where('status = ?', 0)
                    ->order('id', Db::SORT_DESC)
                    ->limit(1)
            );
            if (!empty($token['expires'])) {
                $expiresText = '<p class="description">'
                    . _t('当前验证链接有效期至 %s', date('Y-m-d H:i', (int) $token['expires']))
                    . '</p>';
            }

            $resendUrl = Security::alloc()->getIndex(
                'action/' . self::ACTION_NAME . '?do=resend'
            );

            $html = '<p><span style="display:inline-block;padding:2px 10px;border-radius:3px;'
                . 'background:#fdecea;color:#b32d2e;border:1px solid #f5c6c6;">'
                . _t('邮箱未验证') . '</span></p>'
                . $expiresText
                . '<p><a class="btn btn-s primary" href="' . htmlspecialchars($resendUrl) . '">'
                . _t('重新发送验证邮件') . '</a></p>'
                . '<p class="description">'
                . _t('验证期间不影响您正常使用；超过有效期后可在此处重新发送验证邮件。')
                . '</p>';
        }

        $element = new StatusElement('tuc_email_verify_status', null, null, _t('邮箱验证状态'));
        $element->description($html);
        $form->addItem($element);

        // 保证激活时写入个人配置行，避免个人设置页读取配置报错
        $form->addInput(new Hidden('tuc_marker', null, '1'));
    }

    /**
     * 注册完成钩子：生成 token 并发送验证邮件
     *
     * @param \Widget\Register $register
     */
    public static function onFinishRegister($register)
    {
        try {
            $uid = (int) $register->uid;
            if ($uid <= 0) {
                return;
            }

            $db = Db::get();
            $db->query(
                $db->update('table.users')
                    ->rows(['email_verified' => 0])
                    ->where('uid = ?', $uid)
            );

            self::issueTokenAndMail(
                $uid,
                (string) $register->mail,
                $register->screenName ?: $register->name
            );

            // 用独立 cookie 传递提醒，避开 Register 后续对 __typecho_notice 的覆盖
            \Typecho\Cookie::set('__tuc_flash', json_encode([
                'msg'  => _t('验证链接已发送至您的邮箱，请在规定时间内完成验证。'),
                'type' => 'success',
            ]));
        } catch (\Throwable $e) {
            error_log('[TypechoUserCleaner] onFinishRegister: ' . $e->getMessage());
            \Typecho\Cookie::set('__tuc_flash', json_encode([
                'msg'  => _t('验证邮件发送失败，请稍后在个人设置中重新发送验证邮件。'),
                'type' => 'notice',
            ]));
        }
    }

    /**
     * 生成新的验证 token 并发送验证邮件
     *
     * @param int    $uid
     * @param string $mail
     * @param string $name
     * @throws \Exception
     */
    public static function issueTokenAndMail($uid, $mail, $name = '')
    {
        if (empty($mail)) {
            throw new \Exception('user mail is empty');
        }

        $options = Options::alloc();
        $config = $options->plugin('TypechoUserCleaner');
        $now = (int) $options->time;
        $hours = (int) self::cfg($config, 'expire', 24);
        if ($hours < 1) {
            $hours = 24;
        }

        $token = self::randomToken();
        $db = Db::get();

        // 旧 token 作废，保证一次只有一个有效链接
        $db->query($db->delete(self::TOKEN_TABLE)->where('uid = ?', $uid));
        $db->query(
            $db->insert(self::TOKEN_TABLE)->rows([
                'uid'     => (int) $uid,
                'token'   => $token,
                'created' => $now,
                'expires' => $now + $hours * 3600,
                'status'  => 0,
            ])
        );

        $link = Common::url(
            'action/' . self::ACTION_NAME . '?do=verify&token=' . $token,
            $options->index
        );

        $siteName = $options->title;
        $subjectTpl = (string) self::cfg($config, 'subject', '【{sitename}】请完成邮箱验证');
        $bodyTpl = (string) self::cfg($config, 'body', self::defaultBody());

        $replace = [
            '{sitename}' => htmlspecialchars($siteName),
            '{username}' => htmlspecialchars($name),
            '{link}'     => htmlspecialchars($link),
            '{expire}'   => $hours,
        ];

        $subject = strtr($subjectTpl, $replace);
        $html = strtr($bodyTpl, $replace);
        $text = html_entity_decode(strip_tags($html), ENT_QUOTES, 'UTF-8');

        self::sendMail($config, $mail, $subject, $html, $text, $siteName);
    }

    /**
     * 用户因未验证被删除时发送提醒邮件
     *
     * @param array $user
     */
    public static function sendDeleteNotice(array $user)
    {
        try {
            if (empty($user['mail'])) {
                return;
            }

            $options = Options::alloc();
            $config = $options->plugin('TypechoUserCleaner');
            $siteName = $options->title;
            $siteUrl = $options->siteUrl;

            $subject = '【' . $siteName . '】账号删除提醒';
            $text = $siteName . '（' . $siteUrl . '）提醒您：您因未在规定时间内完成邮件验证而被系统删除，下次使用，请重新注册。';
            $html = '<p><a href="' . htmlspecialchars($siteUrl) . '">'
                . htmlspecialchars($siteName) . '</a>提醒您：</p>'
                . '<p>您因未在规定时间内完成邮件验证而被系统删除，下次使用，请重新注册。</p>';

            self::sendMail($config, $user['mail'], $subject, $html, $text, $siteName);
        } catch (\Throwable $e) {
            error_log('[TypechoUserCleaner] sendDeleteNotice: ' . $e->getMessage());
        }
    }

    /**
     * 通过 SMTP 发送邮件
     *
     * @param mixed  $config
     * @param string $to
     * @param string $subject
     * @param string $html
     * @param string $text
     * @param string $siteName
     * @throws \Exception
     */
    protected static function sendMail($config, $to, $subject, $html, $text, $siteName = '')
    {
        $host = trim((string) self::cfg($config, 'host', ''));
        if ('' === $host) {
            throw new \Exception('SMTP host is not configured');
        }

        $port = (int) self::cfg($config, 'port', 465);
        if ($port <= 0) {
            $port = 465;
        }
        $secure = (string) self::cfg($config, 'secure', 'ssl');
        if (!in_array($secure, ['ssl', 'tls', 'none'], true)) {
            $secure = 'ssl';
        }

        $username = (string) self::cfg($config, 'username', '');
        $password = (string) self::cfg($config, 'password', '');
        $from = trim((string) self::cfg($config, 'from', ''));
        if ('' === $from) {
            $from = $username;
        }
        $fromName = trim((string) self::cfg($config, 'fromName', ''));
        if ('' === $fromName) {
            $fromName = $siteName;
        }

        $smtp = new Smtp($host, $port, $secure, $username, $password);
        $smtp->send($from, $fromName, $to, $subject, $html, $text);
    }

    /**
     * 管理 > 管理 > 用户 页面注入验证状态列
     */
    public static function adminFooter()
    {
        // 注册完成后的邮箱验证提醒（注册请求 redirect 到 adminUrl 后由本钩子捕获）
        self::renderFlashNotice();

        try {
            $script = isset($_SERVER['SCRIPT_NAME']) ? basename($_SERVER['SCRIPT_NAME']) : '';
            if ('manage-users.php' !== $script) {
                return;
            }

            $db = Db::get();
            $rows = $db->fetchAll(
                $db->select('uid', 'email_verified')->from('table.users')
            );

            $map = [];
            foreach ($rows as $row) {
                $map[(int) $row['uid']] = (int) $row['email_verified'] === 1 ? 1 : 0;
            }
        } catch (\Throwable $e) {
            return;
        }

        echo '<script>(function(){';
        echo 'var M=' . json_encode($map) . ';';
        echo <<<'JS'
var table=document.querySelector('table.typecho-list-table');
if(!table||!table.tHead)return;
var headRow=table.tHead.rows[0];
var th=document.createElement('th');
th.className='kit-hidden-mb';
th.textContent='验证状态';
headRow.insertBefore(th,headRow.cells[headRow.cells.length-1]);
var colgroup=table.querySelector('colgroup');
if(colgroup){var col=document.createElement('col');col.setAttribute('width','12%');col.className='kit-hidden-mb';
colgroup.insertBefore(col,colgroup.children[colgroup.children.length-1]);}
var tbody=table.tBodies[0];if(!tbody)return;
tbody.querySelectorAll('tr[id^="user-"]').forEach(function(tr){
  var m=tr.id.match(/user-(\d+)/);if(!m)return;
  var ok=M[parseInt(m[1],10)]===1;
  var td=document.createElement('td');
  td.className='kit-hidden-mb';
  td.innerHTML=ok?'<span style="color:#1e7e34;font-weight:600;">已验证</span>':'<span style="color:#b32d2e;font-weight:600;">未验证</span>';
  tr.insertBefore(td,tr.cells[tr.cells.length-1]);
});
})();</script>
JS;
    }

    /**
     * 渲染注册后的一次性提醒横幅（基于 __tuc_flash cookie）
     */
    private static function renderFlashNotice()
    {
        $flash = \Typecho\Cookie::get('__tuc_flash');
        if (empty($flash)) {
            return;
        }

        // 读后即删，确保只展示一次
        \Typecho\Cookie::delete('__tuc_flash');

        $data = json_decode($flash, true);
        if (empty($data['msg'])) {
            return;
        }

        $success = ($data['type'] ?? '') === 'success';
        $bg = $success ? '#e6f4ea' : '#fdecea';
        $fg = $success ? '#1e7e34' : '#b32d2e';
        $bd = $success ? '#b7dfc1' : '#f5c6c6';

        $payload = json_encode([
            'msg'   => (string) $data['msg'],
            'style' => 'position:fixed;top:10px;left:50%;transform:translateX(-50%);'
                . 'z-index:99999;min-width:300px;max-width:80%;padding:12px 20px;'
                . 'border-radius:4px;box-shadow:0 2px 8px rgba(0,0,0,.2);font-size:14px;'
                . 'background:' . $bg . ';color:' . $fg . ';border:1px solid ' . $bd . ';text-align:center;',
        ]);

        echo '<script>(function(){var p=' . $payload . ';var d=document.createElement("div");'
            . 'd.setAttribute("style",p.style);d.textContent=p.msg;'
            . 'function add(){document.body?document.body.appendChild(d):setTimeout(add,50);}add();'
            . 'setTimeout(function(){d.style.transition="opacity .5s";d.style.opacity="0";'
            . 'setTimeout(function(){d.parentNode&&d.parentNode.removeChild(d);},500);},6000);})();</script>'
            . "\n";
    }

    /**
     * 读取配置项（兼容未保存配置时的默认值）
     *
     * @param mixed  $config
     * @param string $key
     * @param mixed  $default
     * @return mixed
     */
    protected static function cfg($config, $key, $default = null)
    {
        if (null !== $config && isset($config->{$key}) && '' !== $config->{$key}) {
            return $config->{$key};
        }
        return $default;
    }

    /**
     * 生成随机 token
     *
     * @return string
     */
    protected static function randomToken()
    {
        if (function_exists('random_bytes')) {
            return bin2hex(random_bytes(32));
        }
        return md5(uniqid((string) mt_rand(), true) . mt_rand());
    }

    /**
     * 默认邮件正文
     *
     * @return string
     */
    protected static function defaultBody()
    {
        return '<p>您好，{username}：</p>'
            . '<p>欢迎注册 {sitename}！请在 {expire} 小时内点击下面的链接完成邮箱验证：</p>'
            . '<p><a href="{link}">{link}</a></p>'
            . '<p>如果以上链接无法点击，请复制链接到浏览器地址栏访问。</p>'
            . '<p>如非本人操作，请忽略此邮件。</p>';
    }

    /**
     * 识别数据库类型
     *
     * @param Db $db
     * @return string mysql|pgsql|sqlite
     */
    protected static function adapterType(Db $db)
    {
        $class = strtolower(get_class($db->getAdapter()));
        if (false !== strpos($class, 'sqlite')) {
            return 'sqlite';
        }
        if (false !== strpos($class, 'pgsql')) {
            return 'pgsql';
        }
        return 'mysql';
    }

    /**
     * 判断字段是否存在
     *
     * @param Db   $db
     * @param string $table
     * @param string $column
     * @param string $type
     * @return bool
     */
    protected static function columnExists(Db $db, $table, $column, $type)
    {
        try {
            if ('sqlite' === $type) {
                $columns = $db->fetchAll('PRAGMA table_info(' . $table . ')');
                foreach ($columns as $col) {
                    if (isset($col['name']) && $col['name'] === $column) {
                        return true;
                    }
                }
                return false;
            }

            if ('pgsql' === $type) {
                $row = $db->fetchRow(
                    $db->select('column_name')
                        ->from('information_schema.columns')
                        ->where('table_name = ?', $table)
                        ->where('column_name = ?', $column)
                        ->limit(1)
                );
                return !empty($row);
            }

            $like = "'" . str_replace("'", "''", $column) . "'";
            $row = $db->fetchRow('SHOW COLUMNS FROM `' . $table . '` LIKE ' . $like);
            return !empty($row);
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * 创建 token 表
     *
     * @param Db     $db
     * @param string $table
     * @param string $type
     */
    protected static function createTokenTable(Db $db, $table, $type)
    {
        if ('sqlite' === $type) {
            $sql = 'CREATE TABLE IF NOT EXISTS "' . $table . '" ('
                . '"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,'
                . '"uid" INTEGER NOT NULL DEFAULT 0,'
                . '"token" CHAR(64) NOT NULL UNIQUE,'
                . '"created" INTEGER NOT NULL DEFAULT 0,'
                . '"expires" INTEGER NOT NULL DEFAULT 0,'
                . '"status" INTEGER NOT NULL DEFAULT 0)';
        } elseif ('pgsql' === $type) {
            $sql = 'CREATE TABLE IF NOT EXISTS "' . $table . '" ('
                . '"id" SERIAL PRIMARY KEY,'
                . '"uid" INTEGER NOT NULL DEFAULT 0,'
                . '"token" CHAR(64) NOT NULL UNIQUE,'
                . '"created" INTEGER NOT NULL DEFAULT 0,'
                . '"expires" INTEGER NOT NULL DEFAULT 0,'
                . '"status" SMALLINT NOT NULL DEFAULT 0)';
            $db->query($sql);
            $sql = 'CREATE INDEX IF NOT EXISTS "' . $table . '_uid" ON "' . $table . '" ("uid")';
        } else {
            $sql = 'CREATE TABLE IF NOT EXISTS `' . $table . '` ('
                . '`id` INT UNSIGNED NOT NULL AUTO_INCREMENT,'
                . '`uid` INT UNSIGNED NOT NULL DEFAULT 0,'
                . '`token` CHAR(64) NOT NULL,'
                . '`created` INT UNSIGNED NOT NULL DEFAULT 0,'
                . '`expires` INT UNSIGNED NOT NULL DEFAULT 0,'
                . '`status` TINYINT NOT NULL DEFAULT 0,'
                . 'PRIMARY KEY (`id`),'
                . 'UNIQUE KEY `token` (`token`),'
                . 'KEY `uid` (`uid`)'
                . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4';
        }

        $db->query($sql);
    }

    /**
     * 更新 actionTable 选项，注册 / 接管后台动作
     *
     * @param bool $enable
     */
    protected static function updateActionTable($enable)
    {
        $db = Db::get();

        $row = $db->fetchRow(
            $db->select()->from('table.options')
                ->where('name = ?', 'actionTable')
                ->where('user = ?', 0)
                ->limit(1)
        );

        $map = [];
        if (!empty($row['value'])) {
            $tmp = @unserialize($row['value']);
            if (is_array($tmp)) {
                $map = $tmp;
            }
        }

        if ($enable) {
            $map['users-edit'] = '\\' . __NAMESPACE__ . '\\UsersEdit';
            $map[self::ACTION_NAME] = '\\' . __NAMESPACE__ . '\\Action';
        } else {
            unset($map['users-edit'], $map[self::ACTION_NAME]);
        }

        $value = serialize($map);
        if (!empty($row)) {
            $db->query(
                $db->update('table.options')
                    ->rows(['value' => $value])
                    ->where('name = ?', 'actionTable')
                    ->where('user = ?', 0)
            );
        } else {
            $db->query(
                $db->insert('table.options')->rows([
                    'name'  => 'actionTable',
                    'user'  => 0,
                    'value' => $value,
                ])
            );
        }
    }
}

/**
 * 个人设置中的状态展示元素（纯展示，不提交数据）
 */
class StatusElement extends Element
{
    /**
     * @param string|null $name
     * @param array|null $options
     * @return null
     */
    public function input(?string $name = null, ?array $options = null): ?\Typecho\Widget\Helper\Layout
    {
        return null;
    }

    /**
     * @param mixed $value
     */
    protected function inputValue($value)
    {
    }
}
