package com.quizlet.local.cache;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends g {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(long j) {
        super(j);
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
    }
}
