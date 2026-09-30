<?php

namespace TypechoPlugin\TypechoUserCleaner;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

/**
 * 接管后台用户删除动作：
 * 删除未验证用户前向其发送提醒邮件，已验证用户跳过。
 */
class UsersEdit extends \Widget\Users\Edit
{
    /**
     * 删除用户
     */
    public function deleteUser()
    {
        try {
            $uids = $this->request->filter('int')->getArray('uid');
            $db = $this->db;

            // 与核心逻辑一致：最早注册的用户和当前管理员不可删除
            $masterUserId = (int) $db->fetchObject(
                $db->select(['MIN(uid)' => 'num'])->from('table.users')
            )->num;

            foreach ($uids as $uid) {
                $uid = (int) $uid;
                if ($uid <= 0 || $masterUserId === $uid || $uid === (int) $this->user->uid) {
                    continue;
                }

                $user = $db->fetchRow(
                    $db->select('uid', 'name', 'screenName', 'mail', 'email_verified')
                        ->from('table.users')
                        ->where('uid = ?', $uid)
                        ->limit(1)
                );

                if (empty($user)) {
                    continue;
                }

                // 清理该用户的验证 token
                $db->query(
                    $db->delete(Plugin::TOKEN_TABLE)->where('uid = ?', $uid)
                );

                // 未验证用户：发送删除提醒；已验证用户跳过
                if ((int) $user['email_verified'] !== 1 && !empty($user['mail'])) {
                    Plugin::sendDeleteNotice($user);
                }
            }
        } catch (\Throwable $e) {
            error_log('[TypechoUserCleaner] deleteUser: ' . $e->getMessage());
        }

        parent::deleteUser();
    }
}
