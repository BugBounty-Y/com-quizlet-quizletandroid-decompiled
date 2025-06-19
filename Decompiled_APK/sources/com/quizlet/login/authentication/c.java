package com.quizlet.login.authentication;

import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends k {
    public static final c c;

    static {
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        c = new c(new com.quizlet.qutils.string.f(R.string.blocked_by_captcha, C4933y.P(args)), null, 6);
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof c);
    }

    public final int hashCode() {
        return -839001135;
    }

    public final String toString() {
        return "BlockedByCaptcha";
    }
}
