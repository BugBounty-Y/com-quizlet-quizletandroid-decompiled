package com.quizlet.ui.models.webpage;

import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class b extends m {
    public final String a;
    public final int b;

    public b(String str, int i) {
        this.a = str;
        this.b = i;
    }

    @Override // com.quizlet.ui.models.webpage.m
    public final com.quizlet.qutils.string.g a() {
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        return new com.quizlet.qutils.string.f(this.b, C4933y.P(args));
    }

    @Override // com.quizlet.ui.models.webpage.m
    public final String b() {
        return "https://quizlet.com" + this.a;
    }
}
