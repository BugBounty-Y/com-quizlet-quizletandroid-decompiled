package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.user.FullUserResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;
import retrofit2.K;

@Metadata
/* loaded from: classes3.dex */
public interface t {
    @retrofit2.http.o("users/qplus/free-trial")
    Object a(@NotNull kotlin.coroutines.h<? super K<ApiThreeWrapper<FullUserResponse>>> hVar);
}
