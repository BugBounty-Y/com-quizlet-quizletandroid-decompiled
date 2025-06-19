package com.quizlet.login.authentication;

import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i extends k {
    public static final i c;

    static {
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        c = new i(new com.quizlet.qutils.string.f(R.string.signup_region_not_available, C4933y.P(args)), null, 6);
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof i);
    }

    public final int hashCode() {
        return 1103096324;
    }

    public final String toString() {
        return "RegionNotAvailable";
    }
}
