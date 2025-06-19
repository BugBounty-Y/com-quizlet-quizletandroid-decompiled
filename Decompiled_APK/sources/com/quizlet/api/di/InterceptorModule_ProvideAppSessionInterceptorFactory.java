package com.quizlet.api.di;

import com.quizlet.api.okhttp.interceptors.AppSessionInterceptor;
import com.quizlet.infra.contracts.session.a;
import dagger.internal.c;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.s;

/* loaded from: classes2.dex */
public final class InterceptorModule_ProvideAppSessionInterceptorFactory implements c {
    private final c appSessionIdProvider;
    private final c baseUrlProvider;

    @Override // javax.inject.a
    public AppSessionInterceptor get() {
        a appSessionIdProvider = (a) this.appSessionIdProvider.get();
        s baseUrl = (s) this.baseUrlProvider.get();
        Intrinsics.checkNotNullParameter(appSessionIdProvider, "appSessionIdProvider");
        Intrinsics.checkNotNullParameter(baseUrl, "baseUrl");
        return new AppSessionInterceptor(appSessionIdProvider, baseUrl);
    }
}
