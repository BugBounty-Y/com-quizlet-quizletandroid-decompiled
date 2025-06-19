package com.google.android.datatransport.cct.internal;

import android.util.SparseArray;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class A {
    public static final A a;
    public static final /* synthetic */ A[] b;

    /* JADX INFO: Fake field, exist only in values array */
    A EF0;

    static {
        A a2 = new A("NOT_SET", 0);
        A a3 = new A("EVENT_OVERRIDE", 1);
        a = a3;
        b = new A[]{a2, a3};
        SparseArray sparseArray = new SparseArray();
        sparseArray.put(0, a2);
        sparseArray.put(5, a3);
    }

    public static A valueOf(String str) {
        return (A) Enum.valueOf(A.class, str);
    }

    public static A[] values() {
        return (A[]) b.clone();
    }
}
