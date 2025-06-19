package com.quizlet.api.di;

import dagger.internal.c;
import kotlin.jvm.internal.Intrinsics;
import retrofit2.AbstractC5180e;
import retrofit2.C5184i;

/* loaded from: classes2.dex */
public final class QuizletApiClientHelperFactoryModule_ProvideCallAdapterFactoryFactory implements c {
    @Override // javax.inject.a
    public AbstractC5180e get() {
        C5184i c5184i = new C5184i(1);
        Intrinsics.checkNotNullExpressionValue(c5184i, "createSynchronous(...)");
        return c5184i;
    }
}
