package com.quizlet.login.authentication;

import android.content.Context;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class k {
    public final com.quizlet.qutils.string.g a;
    public final com.quizlet.qutils.string.g b;

    public k(com.quizlet.qutils.string.g gVar, com.quizlet.qutils.string.f fVar, int i) {
        fVar = (i & 2) != 0 ? null : fVar;
        this.a = gVar;
        this.b = fVar;
    }

    public final String a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        return this.a.a(context);
    }
}
