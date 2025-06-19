package com.quizlet.api.di;

import com.quizlet.api.cookie.QuizletCookieManager;
import dagger.internal.c;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.n;
import okhttp3.v;

/* loaded from: classes2.dex */
public final class ApiModule_ProvideCookieJarFactory implements c {
    private final ApiModule module;
    private final c quizletCookieManagerProvider;

    @Override // javax.inject.a
    public n get() {
        ApiModule apiModule = this.module;
        QuizletCookieManager quizletCookieManager = (QuizletCookieManager) this.quizletCookieManagerProvider.get();
        apiModule.getClass();
        Intrinsics.checkNotNullParameter(quizletCookieManager, "quizletCookieManager");
        return new v(quizletCookieManager);
    }
}
