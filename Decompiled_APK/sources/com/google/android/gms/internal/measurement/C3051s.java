package com.google.android.gms.internal.measurement;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3554w3;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

/* renamed from: com.google.android.gms.internal.measurement.s, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3051s {
    public final ArrayList a = new ArrayList();
    public final /* synthetic */ int b;

    public C3051s(int i) {
        this.b = i;
    }

    public static C3022m c(C1721Kc c1721Kc, ArrayList arrayList) {
        EnumC3071w enumC3071w = EnumC3071w.ADD;
        AbstractC3554w3.h("FN", arrayList, 2);
        InterfaceC3027n interfaceC3027nA = ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(0));
        InterfaceC3027n interfaceC3027nA2 = ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(1));
        if (!(interfaceC3027nA2 instanceof C2977d)) {
            throw new IllegalArgumentException(AbstractC0147y.d("FN requires an ArrayValue of parameter names found ", interfaceC3027nA2.getClass().getCanonicalName()));
        }
        ArrayList arrayListO = ((C2977d) interfaceC3027nA2).o();
        List arrayList2 = new ArrayList();
        if (arrayList.size() > 2) {
            arrayList2 = arrayList.subList(2, arrayList.size());
        }
        return new C3022m(interfaceC3027nA.zzi(), arrayListO, arrayList2, c1721Kc);
    }

    public static InterfaceC3027n d(C3066v c3066v, Iterator it2, InterfaceC3027n interfaceC3027n) {
        C1721Kc c1721KcG;
        if (it2 != null) {
            while (it2.hasNext()) {
                InterfaceC3027n interfaceC3027n2 = (InterfaceC3027n) it2.next();
                switch (c3066v.a) {
                    case 0:
                        c1721KcG = c3066v.b.g();
                        String str = c3066v.c;
                        c1721KcG.m(str, interfaceC3027n2);
                        ((HashMap) c1721KcG.e).put(str, Boolean.TRUE);
                        break;
                    case 1:
                        c1721KcG = c3066v.b.g();
                        c1721KcG.m(c3066v.c, interfaceC3027n2);
                        break;
                    default:
                        String str2 = c3066v.c;
                        c1721KcG = c3066v.b;
                        c1721KcG.m(str2, interfaceC3027n2);
                        break;
                }
                InterfaceC3027n interfaceC3027nK = c1721KcG.k((C2977d) interfaceC3027n);
                if (interfaceC3027nK instanceof C2987f) {
                    C2987f c2987f = (C2987f) interfaceC3027nK;
                    if ("break".equals(c2987f.b)) {
                        return InterfaceC3027n.Q0;
                    }
                    if ("return".equals(c2987f.b)) {
                        return c2987f;
                    }
                }
            }
        }
        return InterfaceC3027n.Q0;
    }

    public static boolean e(InterfaceC3027n interfaceC3027n, InterfaceC3027n interfaceC3027n2) {
        if (interfaceC3027n.getClass().equals(interfaceC3027n2.getClass())) {
            if ((interfaceC3027n instanceof r) || (interfaceC3027n instanceof C3017l)) {
                return true;
            }
            return interfaceC3027n instanceof C2992g ? (Double.isNaN(interfaceC3027n.g().doubleValue()) || Double.isNaN(interfaceC3027n2.g().doubleValue()) || interfaceC3027n.g().doubleValue() != interfaceC3027n2.g().doubleValue()) ? false : true : interfaceC3027n instanceof C3042q ? interfaceC3027n.zzi().equals(interfaceC3027n2.zzi()) : interfaceC3027n instanceof C2982e ? interfaceC3027n.h().equals(interfaceC3027n2.h()) : interfaceC3027n == interfaceC3027n2;
        }
        if (((interfaceC3027n instanceof r) || (interfaceC3027n instanceof C3017l)) && ((interfaceC3027n2 instanceof r) || (interfaceC3027n2 instanceof C3017l))) {
            return true;
        }
        boolean z = interfaceC3027n instanceof C2992g;
        if (z && (interfaceC3027n2 instanceof C3042q)) {
            return e(interfaceC3027n, new C2992g(interfaceC3027n2.g()));
        }
        boolean z2 = interfaceC3027n instanceof C3042q;
        if ((!z2 || !(interfaceC3027n2 instanceof C2992g)) && !(interfaceC3027n instanceof C2982e)) {
            if (interfaceC3027n2 instanceof C2982e) {
                return e(interfaceC3027n, new C2992g(interfaceC3027n2.g()));
            }
            if ((z2 || z) && (interfaceC3027n2 instanceof InterfaceC3007j)) {
                return e(interfaceC3027n, new C3042q(interfaceC3027n2.zzi()));
            }
            if ((interfaceC3027n instanceof InterfaceC3007j) && ((interfaceC3027n2 instanceof C3042q) || (interfaceC3027n2 instanceof C2992g))) {
                return e(new C3042q(interfaceC3027n.zzi()), interfaceC3027n2);
            }
            return false;
        }
        return e(new C2992g(interfaceC3027n.g()), interfaceC3027n2);
    }

    public static boolean f(InterfaceC3027n interfaceC3027n, InterfaceC3027n interfaceC3027n2) {
        if (interfaceC3027n instanceof InterfaceC3007j) {
            interfaceC3027n = new C3042q(interfaceC3027n.zzi());
        }
        if (interfaceC3027n2 instanceof InterfaceC3007j) {
            interfaceC3027n2 = new C3042q(interfaceC3027n2.zzi());
        }
        if ((interfaceC3027n instanceof C3042q) && (interfaceC3027n2 instanceof C3042q)) {
            return ((C3042q) interfaceC3027n).a.compareTo(((C3042q) interfaceC3027n2).a) < 0;
        }
        double dDoubleValue = interfaceC3027n.g().doubleValue();
        double dDoubleValue2 = interfaceC3027n2.g().doubleValue();
        return (Double.isNaN(dDoubleValue) || Double.isNaN(dDoubleValue2) || (dDoubleValue == 0.0d && dDoubleValue2 == 0.0d) || ((dDoubleValue == 0.0d && dDoubleValue2 == 0.0d) || Double.compare(dDoubleValue, dDoubleValue2) >= 0)) ? false : true;
    }

    public static InterfaceC3027n g(C3066v c3066v, InterfaceC3027n interfaceC3027n, InterfaceC3027n interfaceC3027n2) {
        if (interfaceC3027n instanceof Iterable) {
            return d(c3066v, ((Iterable) interfaceC3027n).iterator(), interfaceC3027n2);
        }
        throw new IllegalArgumentException("Non-iterable type in for...of loop.");
    }

    public static boolean h(InterfaceC3027n interfaceC3027n, InterfaceC3027n interfaceC3027n2) {
        if (interfaceC3027n instanceof InterfaceC3007j) {
            interfaceC3027n = new C3042q(interfaceC3027n.zzi());
        }
        if (interfaceC3027n2 instanceof InterfaceC3007j) {
            interfaceC3027n2 = new C3042q(interfaceC3027n2.zzi());
        }
        return (((interfaceC3027n instanceof C3042q) && (interfaceC3027n2 instanceof C3042q)) || !(Double.isNaN(interfaceC3027n.g().doubleValue()) || Double.isNaN(interfaceC3027n2.g().doubleValue()))) && !f(interfaceC3027n2, interfaceC3027n);
    }

    /* JADX WARN: Removed duplicated region for block: B:508:? A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.internal.measurement.InterfaceC3027n a(java.lang.String r13, com.google.android.gms.internal.ads.C1721Kc r14, java.util.ArrayList r15) {
        /*
            Method dump skipped, instructions count: 3864
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.measurement.C3051s.a(java.lang.String, com.google.android.gms.internal.ads.Kc, java.util.ArrayList):com.google.android.gms.internal.measurement.n");
    }

    public final void b(String str) {
        if (!this.a.contains(AbstractC3554w3.d(str))) {
            throw new IllegalArgumentException("Command not supported");
        }
        throw new UnsupportedOperationException("Command not implemented: ".concat(String.valueOf(str)));
    }
}
