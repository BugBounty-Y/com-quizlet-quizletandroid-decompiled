package com.quizlet.login.authentication;

import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends k {
    public static final d c;

    static {
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        com.quizlet.qutils.string.f fVar = new com.quizlet.qutils.string.f(R.string.email_not_confirmed_message, C4933y.P(args));
        Object[] args2 = new Object[0];
        Intrinsics.checkNotNullParameter(args2, "args");
        c = new d(fVar, new com.quizlet.qutils.string.f(R.string.email_not_confirmed_title, C4933y.P(args2)), 4);
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof d);
    }

    public final int hashCode() {
        return -1632719946;
    }

    public final String toString() {
        return "EmailConfirmationRequired";
    }
}
