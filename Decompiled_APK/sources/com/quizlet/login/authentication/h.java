package com.quizlet.login.authentication;

import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h extends k {
    public static final h c;

    static {
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        c = new h(new com.quizlet.qutils.string.f(R.string.could_not_login, C4933y.P(args)), null, 6);
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof h);
    }

    public final int hashCode() {
        return 1373776564;
    }

    public final String toString() {
        return "Network";
    }
}
