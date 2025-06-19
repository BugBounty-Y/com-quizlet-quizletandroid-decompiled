package com.facebook.internal;

import java.util.EnumSet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public enum F {
    /* JADX INFO: Fake field, exist only in values array */
    EF0("None"),
    c("Enabled"),
    d("RequireConfirm");

    public static final EnumSet b;
    public final long a;

    static {
        EnumSet enumSetAllOf = EnumSet.allOf(F.class);
        Intrinsics.checkNotNullExpressionValue(enumSetAllOf, "allOf(SmartLoginOption::class.java)");
        b = enumSetAllOf;
    }

    F(String str) {
        this.a = j;
    }
}
