package com.quizlet.login.authentication;

import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends k {
    public static final a c;

    static {
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        com.quizlet.qutils.string.f fVar = new com.quizlet.qutils.string.f(R.string.account_already_exists_message, C4933y.P(args));
        Object[] args2 = new Object[0];
        Intrinsics.checkNotNullParameter(args2, "args");
        c = new a(fVar, new com.quizlet.qutils.string.f(R.string.account_already_exists_title, C4933y.P(args2)), 4);
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof a);
    }

    public final int hashCode() {
        return 501874401;
    }

    public final String toString() {
        return "AccountAlreadyExists";
    }
}
