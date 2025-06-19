package com.quizlet.api.di;

import com.quizlet.api.okhttp.interceptors.UserAgentInterceptor;
import dagger.internal.c;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class InterceptorModule_ProvideUserAgentInterceptorFactory implements c {
    private final c versionNameProvider;

    @Override // javax.inject.a
    public UserAgentInterceptor get() {
        String versionName = (String) this.versionNameProvider.get();
        Intrinsics.checkNotNullParameter(versionName, "versionName");
        return new UserAgentInterceptor(versionName);
    }
}
