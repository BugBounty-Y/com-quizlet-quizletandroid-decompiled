package com.quizlet.api.di;

import com.quizlet.api.okhttp.interceptors.AcceptLanguageInterceptor;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class InterceptorModule_ProvideAcceptLanguageInterceptorFactory implements c {
    @Override // javax.inject.a
    public AcceptLanguageInterceptor get() {
        return new AcceptLanguageInterceptor();
    }
}
