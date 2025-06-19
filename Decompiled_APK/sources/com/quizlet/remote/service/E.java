package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.login.magiclink.SendMagicLinkResponse;
import com.quizlet.remote.model.user.FullUserDataResponse;
import com.quizlet.remote.model.user.FullUserResponse;
import com.quizlet.remote.model.user.UserResponse;
import com.quizlet.remote.model.user.delete.DeleteUserAccountResponse;
import java.util.Map;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;
import retrofit2.K;

@Metadata
/* loaded from: classes3.dex */
public interface E {
    @retrofit2.http.f("users/{userId}")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<FullUserResponse>> a(@retrofit2.http.s("userId") long j);

    @retrofit2.http.f("users/search")
    @NotNull
    io.reactivex.rxjava3.core.p<K<ApiThreeWrapper<UserResponse>>> b(@retrofit2.http.t("query") @NotNull String str, @retrofit2.http.t("pagingToken") String str2, @retrofit2.http.t("page") Integer num, @retrofit2.http.t("perPage") int i);

    @retrofit2.http.b("users/current")
    @NotNull
    io.reactivex.rxjava3.core.p<K<DeleteUserAccountResponse>> c();

    @retrofit2.http.f("users/{userIds}")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<UserResponse>> d(@retrofit2.http.s("userIds") @NotNull String str);

    @retrofit2.http.o("send-magic-link")
    @NotNull
    io.reactivex.rxjava3.core.p<SendMagicLinkResponse> e(@NotNull @retrofit2.http.a Map<String, String> map);

    @retrofit2.http.o("users/resend-confirmation")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<FullUserDataResponse>> f();
}
