package com.quizlet.login.authentication;

import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends k {
    public static final e c;

    static {
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        c = new e(new com.quizlet.qutils.string.f(R.string.generic_facebook_error_message, C4933y.P(args)), null, 6);
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof e);
    }

    public final int hashCode() {
        return 2138367757;
    }

    public final String toString() {
        return "FacebookAccount";
    }
}
