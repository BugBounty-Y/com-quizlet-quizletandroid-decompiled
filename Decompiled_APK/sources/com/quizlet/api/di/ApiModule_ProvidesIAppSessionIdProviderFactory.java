package com.quizlet.api.di;

import com.quizlet.api.okhttp.interceptors.AppSessionIdProvider;
import com.quizlet.infra.contracts.session.a;
import dagger.internal.c;
import java.util.Date;

/* loaded from: classes2.dex */
public final class ApiModule_ProvidesIAppSessionIdProviderFactory implements c {
    private final ApiModule module;

    @Override // javax.inject.a
    public a get() {
        this.module.getClass();
        AppSessionIdProvider appSessionIdProvider = new AppSessionIdProvider();
        appSessionIdProvider.b = new Date(Long.MIN_VALUE);
        return appSessionIdProvider;
    }
}
