package com.google.android.datatransport.cct.internal;

import android.util.SparseArray;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class H {
    public static final SparseArray a;
    public static final /* synthetic */ H[] b;

    /* JADX INFO: Fake field, exist only in values array */
    H EF1;

    static {
        H h = new H("UNKNOWN_MOBILE_SUBTYPE", 0);
        H h2 = new H("GPRS", 1);
        H h3 = new H("EDGE", 2);
        H h4 = new H("UMTS", 3);
        H h5 = new H("CDMA", 4);
        H h6 = new H("EVDO_0", 5);
        H h7 = new H("EVDO_A", 6);
        H h8 = new H("RTT", 7);
        H h9 = new H("HSDPA", 8);
        H h10 = new H("HSUPA", 9);
        H h11 = new H("HSPA", 10);
        H h12 = new H("IDEN", 11);
        H h13 = new H("EVDO_B", 12);
        H h14 = new H("LTE", 13);
        H h15 = new H("EHRPD", 14);
        H h16 = new H("HSPAP", 15);
        H h17 = new H("GSM", 16);
        H h18 = new H("TD_SCDMA", 17);
        H h19 = new H("IWLAN", 18);
        H h20 = new H("LTE_CA", 19);
        b = new H[]{h, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20, new H("COMBINED", 20)};
        SparseArray sparseArray = new SparseArray();
        a = sparseArray;
        sparseArray.put(0, h);
        sparseArray.put(1, h2);
        sparseArray.put(2, h3);
        sparseArray.put(3, h4);
        sparseArray.put(4, h5);
        sparseArray.put(5, h6);
        sparseArray.put(6, h7);
        sparseArray.put(7, h8);
        sparseArray.put(8, h9);
        sparseArray.put(9, h10);
        sparseArray.put(10, h11);
        sparseArray.put(11, h12);
        sparseArray.put(12, h13);
        sparseArray.put(13, h14);
        sparseArray.put(14, h15);
        sparseArray.put(15, h16);
        sparseArray.put(16, h17);
        sparseArray.put(17, h18);
        sparseArray.put(18, h19);
        sparseArray.put(19, h20);
    }

    public static H valueOf(String str) {
        return (H) Enum.valueOf(H.class, str);
    }

    public static H[] values() {
        return (H[]) b.clone();
    }
}
