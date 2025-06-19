package com.quizlet.remote.service;

import com.quizlet.remote.model.login.EmailCheckResponse;
import com.quizlet.remote.model.login.ValidateEmailRequest;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface A {
    @retrofit2.http.o("validate-email")
    @NotNull
    io.reactivex.rxjava3.core.p<EmailCheckResponse> a(@NotNull @retrofit2.http.a ValidateEmailRequest validateEmailRequest);
}
