package com.quizlet.quizletandroid.util;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h {
    public final dagger.internal.a a;

    public h(dagger.internal.a onLowMemoryHandler) {
        Intrinsics.checkNotNullParameter(onLowMemoryHandler, "onLowMemoryHandler");
        this.a = onLowMemoryHandler;
    }
}
