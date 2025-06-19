package com.facebook.login;

import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class y {
    public static boolean b(String str) {
        return str != null && (kotlin.text.D.r(str, "publish", false) || kotlin.text.D.r(str, "manage", false) || B.c.contains(str));
    }

    public final B a() {
        if (B.e == null) {
            synchronized (this) {
                B.e = new B();
                Unit unit = Unit.a;
            }
        }
        B b = B.e;
        if (b != null) {
            return b;
        }
        Intrinsics.m("instance");
        throw null;
    }
}
