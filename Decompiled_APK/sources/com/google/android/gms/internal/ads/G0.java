package com.google.android.gms.internal.ads;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class G0 extends AbstractC2863yB {
    public long c;
    public long[] d;
    public long[] e;

    public static Serializable k1(int i, Kn kn) {
        if (i == 0) {
            return Double.valueOf(Double.longBitsToDouble(kn.G()));
        }
        if (i == 1) {
            return Boolean.valueOf(kn.z() == 1);
        }
        if (i == 2) {
            return l1(kn);
        }
        if (i != 3) {
            if (i == 8) {
                return m1(kn);
            }
            if (i != 10) {
                if (i != 11) {
                    return null;
                }
                Date date = new Date((long) Double.longBitsToDouble(kn.G()));
                kn.k(2);
                return date;
            }
            int iC = kn.C();
            ArrayList arrayList = new ArrayList(iC);
            for (int i2 = 0; i2 < iC; i2++) {
                Serializable serializableK1 = k1(kn.z(), kn);
                if (serializableK1 != null) {
                    arrayList.add(serializableK1);
                }
            }
            return arrayList;
        }
        HashMap map = new HashMap();
        while (true) {
            String strL1 = l1(kn);
            int iZ = kn.z();
            if (iZ == 9) {
                return map;
            }
            Serializable serializableK12 = k1(iZ, kn);
            if (serializableK12 != null) {
                map.put(strL1, serializableK12);
            }
        }
    }

    public static String l1(Kn kn) {
        int iD = kn.D();
        int i = kn.b;
        kn.k(iD);
        return new String(kn.a, i, iD);
    }

    public static HashMap m1(Kn kn) {
        int iC = kn.C();
        HashMap map = new HashMap(iC);
        for (int i = 0; i < iC; i++) {
            String strL1 = l1(kn);
            Serializable serializableK1 = k1(kn.z(), kn);
            if (serializableK1 != null) {
                map.put(strL1, serializableK1);
            }
        }
        return map;
    }
}
