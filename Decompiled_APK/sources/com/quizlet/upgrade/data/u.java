package com.quizlet.upgrade.data;

import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class u extends v {
    public static final u b = new u(false);
    public static final com.quizlet.qutils.string.f c;
    public static final int d;

    static {
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        c = new com.quizlet.qutils.string.f(R.string.disclaimer_english_textbooks, C4933y.P(args));
        d = R.string.disclaimer_english_textbooks;
    }

    @Override // com.quizlet.upgrade.data.v
    public final com.quizlet.qutils.string.g a() {
        return c;
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return Integer.valueOf(d);
    }
}
