package com.quizlet.ui.models.content.home;

import com.quizlet.qutils.string.g;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class f {
    public final int a;
    public final int b;

    public f(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    public g a() {
        return b();
    }

    public g b() {
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        return new com.quizlet.qutils.string.f(this.b, C4933y.P(args));
    }
}
