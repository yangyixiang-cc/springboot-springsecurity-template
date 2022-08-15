package com.example.sstest.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.example.sstest.bean.ResponseResult;
import com.example.sstest.bean.User;

public interface UserService extends IService<User> {

    User getUserOneByUsername(String username);


    boolean addUserOne(String username,String password);

    ResponseResult login(User user);

    ResponseResult logout();

}
