package com.quizlet.upgrade.data;

import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class w implements B {
    public static final w a = new w();
    public static final com.quizlet.qutils.string.f b;

    static {
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        b = new com.quizlet.qutils.string.f(R.string.this_is_your_current_plan, C4933y.P(args));
    }

    @Override // com.quizlet.upgrade.data.B
    public final boolean a() {
        return false;
    }

    @Override // com.quizlet.upgrade.data.B
    public final com.quizlet.qutils.string.f b() {
        return b;
    }
}
