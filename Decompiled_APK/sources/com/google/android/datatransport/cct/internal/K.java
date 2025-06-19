package com.google.android.datatransport.cct.internal;

import android.util.SparseArray;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class K {
    public static final K a;
    public static final /* synthetic */ K[] b;

    static {
        K k = new K("DEFAULT", 0);
        a = k;
        K k2 = new K("UNMETERED_ONLY", 1);
        K k3 = new K("UNMETERED_OR_DAILY", 2);
        K k4 = new K("FAST_IF_RADIO_AWAKE", 3);
        K k5 = new K("NEVER", 4);
        K k6 = new K("UNRECOGNIZED", 5);
        b = new K[]{k, k2, k3, k4, k5, k6};
        SparseArray sparseArray = new SparseArray();
        sparseArray.put(0, k);
        sparseArray.put(1, k2);
        sparseArray.put(2, k3);
        sparseArray.put(3, k4);
        sparseArray.put(4, k5);
        sparseArray.put(-1, k6);
    }

    public static K valueOf(String str) {
        return (K) Enum.valueOf(K.class, str);
    }

    public static K[] values() {
        return (K[]) b.clone();
    }
}
