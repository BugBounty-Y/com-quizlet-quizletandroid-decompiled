package com.google.android.datatransport.cct.internal;

import android.util.SparseArray;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class I {
    public static final SparseArray a;
    public static final /* synthetic */ I[] b;

    /* JADX INFO: Fake field, exist only in values array */
    I EF1;

    static {
        I i = new I("MOBILE", 0);
        I i2 = new I("WIFI", 1);
        I i3 = new I("MOBILE_MMS", 2);
        I i4 = new I("MOBILE_SUPL", 3);
        I i5 = new I("MOBILE_DUN", 4);
        I i6 = new I("MOBILE_HIPRI", 5);
        I i7 = new I("WIMAX", 6);
        I i8 = new I("BLUETOOTH", 7);
        I i9 = new I("DUMMY", 8);
        I i10 = new I("ETHERNET", 9);
        I i11 = new I("MOBILE_FOTA", 10);
        I i12 = new I("MOBILE_IMS", 11);
        I i13 = new I("MOBILE_CBS", 12);
        I i14 = new I("WIFI_P2P", 13);
        I i15 = new I("MOBILE_IA", 14);
        I i16 = new I("MOBILE_EMERGENCY", 15);
        I i17 = new I("PROXY", 16);
        I i18 = new I("VPN", 17);
        I i19 = new I("NONE", 18);
        b = new I[]{i, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12, i13, i14, i15, i16, i17, i18, i19};
        SparseArray sparseArray = new SparseArray();
        a = sparseArray;
        sparseArray.put(0, i);
        sparseArray.put(1, i2);
        sparseArray.put(2, i3);
        sparseArray.put(3, i4);
        sparseArray.put(4, i5);
        sparseArray.put(5, i6);
        sparseArray.put(6, i7);
        sparseArray.put(7, i8);
        sparseArray.put(8, i9);
        sparseArray.put(9, i10);
        sparseArray.put(10, i11);
        sparseArray.put(11, i12);
        sparseArray.put(12, i13);
        sparseArray.put(13, i14);
        sparseArray.put(14, i15);
        sparseArray.put(15, i16);
        sparseArray.put(16, i17);
        sparseArray.put(17, i18);
        sparseArray.put(-1, i19);
    }

    public static I valueOf(String str) {
        return (I) Enum.valueOf(I.class, str);
    }

    public static I[] values() {
        return (I[]) b.clone();
    }
}
