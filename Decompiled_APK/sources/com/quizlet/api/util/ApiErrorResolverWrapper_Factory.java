package com.quizlet.api.util;

import android.content.Context;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class ApiErrorResolverWrapper_Factory implements c {
    private final c contextProvider;

    @Override // javax.inject.a
    public ApiErrorResolverWrapper get() {
        return new ApiErrorResolverWrapper((Context) this.contextProvider.get());
    }
}
