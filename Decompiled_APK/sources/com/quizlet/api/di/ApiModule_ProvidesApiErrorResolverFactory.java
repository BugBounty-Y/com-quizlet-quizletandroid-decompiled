package com.quizlet.api.di;

import com.quizlet.api.util.ApiErrorResolver;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class ApiModule_ProvidesApiErrorResolverFactory implements c {
    private final ApiModule module;

    @Override // javax.inject.a
    public ApiErrorResolver get() {
        this.module.getClass();
        return ApiErrorResolver.a;
    }
}
