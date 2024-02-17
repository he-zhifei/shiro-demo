package com.zhifei.controller;

import com.zhifei.plugin.exception.annotation.GlobalException;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@GlobalException
@RestController
public class TestController {

    @GetMapping("/test1")
    public String test1() {
        return "test1";
    }

//    @RequiresRoles({"admin"})
    @RequiresPermissions({"user:list"})
    @GetMapping("/test2")
    public String test2() {
        return "test2";
    }

    @RequiresPermissions({"user:del"})
    @GetMapping("/test3")
    public String test3() {
        return "test3";
    }
}
