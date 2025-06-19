package com.google.android.gms.ads.internal.util;

import com.google.android.gms.internal.ads.AbstractC2930zt;
import com.google.android.gms.internal.ads.At;
import com.google.android.gms.internal.ads.C2883yp;
import com.google.android.gms.internal.ads.Y7;
import java.util.Iterator;

/* loaded from: classes2.dex */
public abstract class A extends com.google.android.gms.ads.internal.util.client.i {
    public static void l(String str) {
        if (!m() || str == null || str.length() <= 4000) {
            return;
        }
        C2883yp c2883yp = com.google.android.gms.ads.internal.util.client.i.a;
        Iterator itE = ((At) c2883yp.b).e(c2883yp, str);
        while (true) {
            AbstractC2930zt abstractC2930zt = (AbstractC2930zt) itE;
            if (!abstractC2930zt.hasNext()) {
                return;
            }
        }
    }

    public static boolean m() {
        return com.google.android.gms.ads.internal.util.client.i.k(2) && ((Boolean) Y7.a.o()).booleanValue();
    }
}
