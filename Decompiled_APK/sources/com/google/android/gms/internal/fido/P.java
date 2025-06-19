package com.google.android.gms.internal.fido;

import java.util.Comparator;
import java.util.Objects;

/* loaded from: classes2.dex */
public abstract class P {
    public static final Comparator a;

    static {
        Comparator comparator;
        try {
            Object[] enumConstants = Class.forName(P.class.getName().concat("$UnsafeComparator")).getEnumConstants();
            Objects.requireNonNull(enumConstants);
            comparator = (Comparator) enumConstants[0];
        } catch (Throwable unused) {
            comparator = O.a;
        }
        a = comparator;
    }
}
