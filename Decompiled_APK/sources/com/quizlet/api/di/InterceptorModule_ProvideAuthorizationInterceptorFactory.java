package com.quizlet.api.di;

import com.quizlet.api.okhttp.interceptors.AuthorizationInterceptor;
import com.quizlet.data.token.a;
import dagger.internal.c;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.s;

/* loaded from: classes2.dex */
public final class InterceptorModule_ProvideAuthorizationInterceptorFactory implements c {
    private final c accessTokenProvider;
    private final c baseUrlProvider;
    private final c clientIdProvider;

    @Override // javax.inject.a
    public AuthorizationInterceptor get() {
        a accessTokenProvider = (a) this.accessTokenProvider.get();
        s baseUrl = (s) this.baseUrlProvider.get();
        String clientId = (String) this.clientIdProvider.get();
        Intrinsics.checkNotNullParameter(accessTokenProvider, "accessTokenProvider");
        Intrinsics.checkNotNullParameter(baseUrl, "baseUrl");
        Intrinsics.checkNotNullParameter(clientId, "clientId");
        return new AuthorizationInterceptor(accessTokenProvider, baseUrl, clientId);
    }
}
