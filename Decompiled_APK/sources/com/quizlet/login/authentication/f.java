package com.quizlet.login.authentication;

import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends k {
    public static final f c;

    static {
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        c = new f(new com.quizlet.qutils.string.f(R.string.error_accessing_google, C4933y.P(args)), null, 6);
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof f);
    }

    public final int hashCode() {
        return 1876809146;
    }

    public final String toString() {
        return "GoogleAccount";
    }
}
