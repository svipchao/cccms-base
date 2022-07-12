<?php
declare(strict_types=1);

namespace cccms;

use stdClass;
use think\{App, Request};
use cccms\services\{InitService, LogService, AuthService, NodeService};

/**
 * 基础类
 */
abstract class Base extends stdClass
{
    /**
     * 应用实例
     * @var App
     */
    protected App $app;

    /**
     * @var Request
     */
    protected Request $request;

    /**
     * @var Model
     */
    protected Model $model;

    /**
     * 构造方法
     * @access public
     * @param App $app 应用对象
     */
    public function __construct(App $app)
    {
        $this->app = $app;
        $this->request = $this->app->request;

        // 设置过滤方法
        $this->request->filter(['htmlspecialchars', 'trim']);

        // 初始化系统运行缓存
        $this->initCache();

        // 验证请求
        $this->check();

        // 控制器初始化
        $this->init();
    }

    // 初始化
    protected function init()
    {
    }

    /**
     * 初始化系统运行缓存
     * @return void
     */
    protected function initCache()
    {
        // 调试模式清除缓存
        if ($this->app->isDebug()) $this->app->cache->clear();
        // 权限节点
        if (empty($this->app->cache->get('SysNodes'))) NodeService::instance()->getNodesInfo();
        // 配置文件
        if (empty($this->app->cache->get('SysConfig'))) InitService::instance()->getConfigs();
        // 表信息
        if (empty($this->app->cache->get('Tables'))) InitService::instance()->getTables();
        // 数据条件
        if (empty($this->app->cache->get('SysData'))) InitService::instance()->getData();
    }

    /**
     * 验证请求
     */
    protected function check(): bool
    {
        $node = NodeService::instance()->getNode(_getNode());
        if (empty($node)) {
            _result(['code' => 404, 'msg' => '页面不存在']);
        }
        // 判断访问方式是否符合注解
        if (!in_array($this->request->method(), $node['methods'])) {
            _result(['code' => 405, 'msg' => '客户端请求中的方法被禁止']);
        }
        // 判断返回编码是否符合注解
        if (!in_array(_getEnCode(), $node['encode'])) {
            _result(['code' => 405, 'msg' => '禁止此编码类型']);
        }
        // 检测是否需要验证登录
        if ($node['login']) {
            // 判断是否登陆
            if (!_getAccessToken()) {
                _result(['code' => 401, 'msg' => '请登陆']);
            }
            // 判断是否需要验证权限 检查用户是否拥有权限
            if ($node['auth'] && !AuthService::instance()->isAuth(_getNode())) {
                _result(['code' => 403, 'msg' => '权限不足']);
            }
            // 记录日志
            if (_config('log.logClose')) {
                LogService::instance()->log($node);
            }
        }
        return true;
    }
}