package com.google.android.gms.internal.mlkit_vision_common;

import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.measurement.AbstractC2997h;
import com.google.android.gms.internal.measurement.C2977d;
import com.google.android.gms.internal.measurement.C2987f;
import com.google.android.gms.internal.measurement.C2992g;
import com.google.android.gms.internal.measurement.C3022m;
import com.google.android.gms.internal.measurement.C3056t;
import com.google.android.gms.internal.measurement.InterfaceC3027n;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.u3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3542u3 {
    public static final /* synthetic */ int a = 0;

    public static C2977d a(C2977d c2977d, C1721Kc c1721Kc, C3022m c3022m, Boolean bool, Boolean bool2) {
        C2977d c2977d2 = new C2977d();
        Iterator itN = c2977d.n();
        while (itN.hasNext()) {
            int iIntValue = ((Integer) itN.next()).intValue();
            if (c2977d.t(iIntValue)) {
                InterfaceC3027n interfaceC3027nD = c3022m.d(c1721Kc, Arrays.asList(c2977d.i(iIntValue), new C2992g(Double.valueOf(iIntValue)), c2977d));
                if (interfaceC3027nD.h().equals(bool)) {
                    break;
                }
                if (bool2 == null || interfaceC3027nD.h().equals(bool2)) {
                    c2977d2.s(iIntValue, interfaceC3027nD);
                }
            }
        }
        return c2977d2;
    }

    public static InterfaceC3027n b(C2977d c2977d, C1721Kc c1721Kc, ArrayList arrayList, boolean z) {
        InterfaceC3027n interfaceC3027nD;
        AbstractC3554w3.h("reduce", arrayList, 1);
        AbstractC3554w3.i(2, "reduce", arrayList);
        InterfaceC3027n interfaceC3027nA = ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(0));
        if (!(interfaceC3027nA instanceof AbstractC2997h)) {
            throw new IllegalArgumentException("Callback should be a method");
        }
        if (arrayList.size() == 2) {
            interfaceC3027nD = ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(1));
            if (interfaceC3027nD instanceof C2987f) {
                throw new IllegalArgumentException("Failed to parse initial value");
            }
        } else {
            if (c2977d.e() == 0) {
                throw new IllegalStateException("Empty array with no initial value error");
            }
            interfaceC3027nD = null;
        }
        AbstractC2997h abstractC2997h = (AbstractC2997h) interfaceC3027nA;
        int iE = c2977d.e();
        int i = z ? 0 : iE - 1;
        int i2 = z ? iE - 1 : 0;
        int i3 = true == z ? 1 : -1;
        if (interfaceC3027nD == null) {
            interfaceC3027nD = c2977d.i(i);
            i += i3;
        }
        while ((i2 - i) * i3 >= 0) {
            if (c2977d.t(i)) {
                interfaceC3027nD = abstractC2997h.d(c1721Kc, Arrays.asList(interfaceC3027nD, c2977d.i(i), new C2992g(Double.valueOf(i)), c2977d));
                if (interfaceC3027nD instanceof C2987f) {
                    throw new IllegalStateException("Reduce operation failed");
                }
                i += i3;
            } else {
                i += i3;
            }
        }
        return interfaceC3027nD;
    }
}
