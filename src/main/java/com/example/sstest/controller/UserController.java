package com.example.sstest.controller;

import com.example.sstest.bean.ResponseResult;
import com.example.sstest.bean.User;
import com.example.sstest.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/login")
    public ResponseResult login(
            @RequestBody User user
    ){
        return userService.login(user);
    }

    @GetMapping("/hello")
    @PreAuthorize("hasAuthority('system:dept:list')") //判断访问者是否有test权限,权限就是一个个名称，如 admin 管理者 user 普通用户等
    public String hello(){
        return "hello";
    }

    @GetMapping("/logout")
    public ResponseResult logout(){
        return userService.logout();
    }

}
