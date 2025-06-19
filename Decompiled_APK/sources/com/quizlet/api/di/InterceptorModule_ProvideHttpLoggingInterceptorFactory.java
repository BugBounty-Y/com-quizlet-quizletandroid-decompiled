package com.quizlet.api.di;

import com.google.firebase.components.n;
import dagger.internal.c;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.logging.a;
import okhttp3.logging.b;

/* loaded from: classes2.dex */
public final class InterceptorModule_ProvideHttpLoggingInterceptorFactory implements c {
    private final c isDebugBuildProvider;

    @Override // javax.inject.a
    public b get() {
        boolean zBooleanValue = ((Boolean) this.isDebugBuildProvider.get()).booleanValue();
        n logger = new n(28);
        Intrinsics.checkNotNullParameter(logger, "logger");
        b bVar = new b();
        bVar.a = M.a;
        bVar.b = a.a;
        a aVar = zBooleanValue ? a.b : a.a;
        Intrinsics.checkNotNullParameter(aVar, "<set-?>");
        bVar.b = aVar;
        return bVar;
    }
}
