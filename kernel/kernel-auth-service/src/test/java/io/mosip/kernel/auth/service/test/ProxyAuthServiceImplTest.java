package io.mosip.kernel.auth.service.test;


import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.kernel.auth.defaultimpl.config.MosipEnvironment;
import io.mosip.kernel.auth.defaultimpl.constant.AuthConstant;
import io.mosip.kernel.auth.defaultimpl.exception.AuthManagerException;
import io.mosip.kernel.auth.defaultimpl.repository.impl.KeycloakImpl;
import io.mosip.kernel.auth.defaultimpl.service.OTPService;
import io.mosip.kernel.auth.defaultimpl.service.TokenService;
import io.mosip.kernel.auth.defaultimpl.service.UinService;
import io.mosip.kernel.auth.defaultimpl.service.impl.ProxyAuthServiceImpl;
import io.mosip.kernel.auth.defaultimpl.util.ProxyTokenGenerator;
import io.mosip.kernel.auth.defaultimpl.util.TokenGenerator;
import io.mosip.kernel.auth.defaultimpl.util.TokenValidator;
import io.mosip.kernel.core.authmanager.model.*;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.List;


@RunWith(MockitoJUnitRunner.class)
public class ProxyAuthServiceImplTest {
    @Mock
    private ProxyTokenGenerator proxyTokenGenarator;

    @Mock
    KeycloakImpl keycloakImpl;

    @Mock
    TokenGenerator tokenGenerator;

    @Mock
    TokenValidator tokenValidator;

    @Mock
    TokenService customTokenServices;

    @Mock
    OTPService oTPService;

    @Mock
    UinService uinService;

    @Mock
    MosipEnvironment mosipEnvironment;

    @Mock
    ObjectMapper objectmapper;

    @InjectMocks
    ProxyAuthServiceImpl proxyAuthServiceImpl;


    @Test
    public void authenticateWithOtp_WithValidUIN_ThenPass() throws Exception {
        OtpUser otpUser=new OtpUser();
        otpUser.setUseridtype("UIN");
        List<String> channel =new ArrayList<>();
        channel.add("MOBILE");
        otpUser.setOtpChannel(channel);
        otpUser.setAppId("mosip");

        AuthNResponseDto authResponseDto=new AuthNResponseDto();
        authResponseDto.setMessage("success validated");
        authResponseDto.setStatus(AuthConstant.SUCCESS_STATUS);
        Mockito.when(oTPService.sendOTPForUin(Mockito.any(),Mockito.any(),Mockito.anyString())).thenReturn(authResponseDto);
        AuthNResponseDto authNResponseDto = proxyAuthServiceImpl.authenticateWithOtp(otpUser);
        Assert.assertEquals(authNResponseDto.getStatus(),AuthConstant.SUCCESS_STATUS);
    }


    @Test
    public void authenticateWithOtp_WithproxyOtpAsTrue_ThenPass() throws Exception {

        ReflectionTestUtils.setField(proxyAuthServiceImpl, "proxyOtp", true);
        OtpUser otpUser=new OtpUser();
        otpUser.setUseridtype("UIN");
        List<String> channel =new ArrayList<>();
        channel.add("MOBILE");
        otpUser.setOtpChannel(channel);
        otpUser.setAppId("mosip");

        AuthNResponseDto authResponseDto=new AuthNResponseDto();
        authResponseDto.setMessage("success validated");
        authResponseDto.setStatus(AuthConstant.SUCCESS_STATUS);
        Mockito.when(oTPService.sendOTPForUin(Mockito.any(),Mockito.any(),Mockito.anyString())).thenReturn(authResponseDto);
        AuthNResponseDto authNResponseDto = proxyAuthServiceImpl.authenticateWithOtp(otpUser);
        Assert.assertEquals(authNResponseDto.getStatus(),AuthConstant.SUCCESS_STATUS);
    }

    @Test
    public void authenticateWithOtp_WithUserId_ThenPass() throws Exception {
        OtpUser otpUser=new OtpUser();
        otpUser.setUseridtype("USERID");
        List<String> channel =new ArrayList<>();
        channel.add("MOBILE");
        otpUser.setOtpChannel(channel);
        otpUser.setAppId("mosip");

        AuthNResponseDto authResponseDto=new AuthNResponseDto();
        authResponseDto.setMessage("success validated");
        authResponseDto.setStatus(AuthConstant.SUCCESS_STATUS);
        Mockito.when(oTPService.sendOTP(Mockito.any(),Mockito.any(),Mockito.anyString())).thenReturn(authResponseDto);
        AuthNResponseDto authNResponseDto = proxyAuthServiceImpl.authenticateWithOtp(otpUser);
        Assert.assertEquals(authNResponseDto.getStatus(),AuthConstant.SUCCESS_STATUS);
    }

    @Test
    public void authenticateWithOtp_WithInvalidDetails_ThenFail() throws Exception {
        OtpUser otpUser=new OtpUser();
        otpUser.setUseridtype("XXX");
        List<String> channel =new ArrayList<>();
        channel.add("MOBILE");
        otpUser.setOtpChannel(channel);
        otpUser.setAppId("mosip");

        try{
            proxyAuthServiceImpl.authenticateWithOtp(otpUser);
            Assert.fail();
        }catch (AuthManagerException e){
            Assert.assertEquals(e.getMessage(),"Invalid User Id type");
        }
    }

    @Test
    public void authenticateUserWithOtp_ValidDatails_thenPass() throws Exception {
        UserOtp userOtp=new UserOtp();
        userOtp.setOtp("1234");
        userOtp.setUserId("1234");
        userOtp.setAppId("mosip");


        MosipUserTokenDto mosipUserTokenDto=new MosipUserTokenDto();
        mosipUserTokenDto.setToken("1234");
        mosipUserTokenDto.setMessage("success validated");
        mosipUserTokenDto.setRefreshToken("1234");
        mosipUserTokenDto.setExpTime(1234L);
        mosipUserTokenDto.setStatus(AuthConstant.SUCCESS_STATUS);
        mosipUserTokenDto.setMosipUserDto(new MosipUserDto());

        Mockito.when(oTPService.validateOTP(Mockito.any(),Mockito.anyString(),Mockito.anyString())).thenReturn(mosipUserTokenDto);
        AuthNResponseDto authNResponseDto = proxyAuthServiceImpl.authenticateUserWithOtp(userOtp);
        Assert.assertEquals(authNResponseDto.getStatus(),AuthConstant.SUCCESS_STATUS);
    }

    @Test
    public void authenticateUserWithOtp_WithproxyOtpAsTrue_ThenPass() throws Exception {

        LoginUser loginUser=new LoginUser();
        loginUser.setUserName("1234");
        loginUser.setPassword("1234");
        loginUser.setAppId("mosip");
        proxyAuthServiceImpl.authenticateUser(loginUser);
    }


}


