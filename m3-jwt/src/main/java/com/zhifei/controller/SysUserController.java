package com.zhifei.controller;

import com.zhifei.entity.SysUser;
import com.zhifei.plugin.exception.annotation.GlobalException;
import com.zhifei.plugin.exception.entity.R;
import com.zhifei.service.SysUserService;
import com.zhifei.vo.UserVo;
import org.apache.shiro.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@GlobalException
@Validated
@RestController
@RequestMapping("/sysUser")
public class SysUserController {

    @Autowired
    private SysUserService sysUserService;

    /**
     * 登录，同时，在注册时，要把加密盐和hash次数保存到数据库
     * @param sysUser
     * @return
     */
    @PostMapping("/login")
    public R login(@RequestBody @Validated SysUser sysUser) {
        UserVo userVo = sysUserService.login(sysUser);
        return R.success().data(userVo);
    }

    /**
     * 退出登录
     * @return
     */
    @GetMapping("/logout")
    public R logout() {
        SecurityUtils.getSubject().logout();
        return R.success().message("已退出登录");
    }

}
