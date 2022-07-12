<?php
declare(strict_types=1);

namespace cccms\services;

use cccms\Service;
use app\admin\model\SysLog;

class LogService extends Service
{
    /**
     * 记录日志
     * @param array 权限节点信息
     * @return bool
     */
    public function log(array $node = []): bool
    {
        // 请求类型
        $method = $this->app->request->method();
        // 需要监控的请求类型
        $log_methods = array_map('strtolower', _config('log.logMethods', []));
        // 不需要登陆的节点不记录 || 不需要监控的请求类型不记录
        if (!$node['login'] || !in_array(strtolower($method), $log_methods)) return true;
        // 请求参数 排除掉不需要记录的参数
        $request_param = $this->app->request->except(_config('log.logNoParams', []));
        // 隐藏私密信息
        if (isset($request_param['password'])) {
            $request_param['password'] = '********';
        }
        if (isset($request_param['token'])) {
            $request_param['token'] = '********';
        }
        $data = [
            'user_id' => AuthService::instance()->getUserInfo('id'),
            'name' => ($node['parentTitle'] ?: '空') . '-' . $node['title'],
            'node' => $node['currentNode'],
            'req_ip' => $this->app->request->ip(),
            'req_method' => $method,
            'req_param' => json_encode($request_param, JSON_UNESCAPED_UNICODE),
            'req_ua' => $this->app->request->server('HTTP_USER_AGENT'),
        ];
        return SysLog::mk()->save($data);
    }
}