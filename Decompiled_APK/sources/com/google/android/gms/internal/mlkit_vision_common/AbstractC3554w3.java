package com.google.android.gms.internal.mlkit_vision_common;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.measurement.C2977d;
import com.google.android.gms.internal.measurement.C2982e;
import com.google.android.gms.internal.measurement.C2992g;
import com.google.android.gms.internal.measurement.C3012k;
import com.google.android.gms.internal.measurement.C3017l;
import com.google.android.gms.internal.measurement.C3042q;
import com.google.android.gms.internal.measurement.EnumC3071w;
import com.google.android.gms.internal.measurement.InterfaceC3027n;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.w3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3554w3 {
    public static final /* synthetic */ int a = 0;

    public static double a(double d) {
        if (Double.isNaN(d)) {
            return 0.0d;
        }
        if (Double.isInfinite(d) || d == 0.0d || d == 0.0d) {
            return d;
        }
        return (d > 0.0d ? 1 : -1) * Math.floor(Math.abs(d));
    }

    public static int b(double d) {
        if (Double.isNaN(d) || Double.isInfinite(d) || d == 0.0d) {
            return 0;
        }
        return (int) (((d > 0.0d ? 1 : -1) * Math.floor(Math.abs(d))) % 4.294967296E9d);
    }

    public static void c(C1721Kc c1721Kc) {
        int iB = b(c1721Kc.l("runtime.counter").g().doubleValue() + 1.0d);
        if (iB > 1000000) {
            throw new IllegalStateException("Instructions allowed exceeded");
        }
        c1721Kc.n("runtime.counter", new C2992g(Double.valueOf(iB)));
    }

    public static EnumC3071w d(String str) throws NumberFormatException {
        EnumC3071w enumC3071w = null;
        if (str != null && !str.isEmpty()) {
            enumC3071w = (EnumC3071w) EnumC3071w.v1.get(Integer.valueOf(Integer.parseInt(str)));
        }
        if (enumC3071w != null) {
            return enumC3071w;
        }
        throw new IllegalArgumentException(AbstractC0147y.d("Unsupported commandId ", str));
    }

    public static Object e(InterfaceC3027n interfaceC3027n) {
        if (InterfaceC3027n.R0.equals(interfaceC3027n)) {
            return null;
        }
        if (InterfaceC3027n.Q0.equals(interfaceC3027n)) {
            return "";
        }
        if (interfaceC3027n instanceof C3012k) {
            return f((C3012k) interfaceC3027n);
        }
        if (!(interfaceC3027n instanceof C2977d)) {
            return !interfaceC3027n.g().isNaN() ? interfaceC3027n.g() : interfaceC3027n.zzi();
        }
        ArrayList arrayList = new ArrayList();
        C2977d c2977d = (C2977d) interfaceC3027n;
        c2977d.getClass();
        int i = 0;
        while (i < c2977d.e()) {
            if (i >= c2977d.e()) {
                throw new NoSuchElementException(android.support.v4.media.session.a.f(i, "Out of bounds index: "));
            }
            int i2 = i + 1;
            Object objE = e(c2977d.i(i));
            if (objE != null) {
                arrayList.add(objE);
            }
            i = i2;
        }
        return arrayList;
    }

    public static HashMap f(C3012k c3012k) {
        HashMap map = new HashMap();
        Iterator it2 = new ArrayList(c3012k.a.keySet()).iterator();
        while (it2.hasNext()) {
            String str = (String) it2.next();
            Object objE = e(c3012k.a(str));
            if (objE != null) {
                map.put(str, objE);
            }
        }
        return map;
    }

    public static void g(String str, List list, int i) {
        if (list.size() == i) {
            return;
        }
        throw new IllegalArgumentException(str + " operation requires " + i + " parameters found " + list.size());
    }

    public static void h(String str, List list, int i) {
        if (list.size() >= i) {
            return;
        }
        throw new IllegalArgumentException(str + " operation requires at least " + i + " parameters found " + list.size());
    }

    public static void i(int i, String str, ArrayList arrayList) {
        if (arrayList.size() <= i) {
            return;
        }
        throw new IllegalArgumentException(str + " operation requires at most " + i + " parameters found " + arrayList.size());
    }

    public static boolean j(InterfaceC3027n interfaceC3027n) {
        if (interfaceC3027n == null) {
            return false;
        }
        Double dG = interfaceC3027n.g();
        return !dG.isNaN() && dG.doubleValue() >= 0.0d && dG.equals(Double.valueOf(Math.floor(dG.doubleValue())));
    }

    public static boolean k(InterfaceC3027n interfaceC3027n, InterfaceC3027n interfaceC3027n2) {
        if (!interfaceC3027n.getClass().equals(interfaceC3027n2.getClass())) {
            return false;
        }
        if ((interfaceC3027n instanceof com.google.android.gms.internal.measurement.r) || (interfaceC3027n instanceof C3017l)) {
            return true;
        }
        if (!(interfaceC3027n instanceof C2992g)) {
            return interfaceC3027n instanceof C3042q ? interfaceC3027n.zzi().equals(interfaceC3027n2.zzi()) : interfaceC3027n instanceof C2982e ? interfaceC3027n.h().equals(interfaceC3027n2.h()) : interfaceC3027n == interfaceC3027n2;
        }
        if (Double.isNaN(interfaceC3027n.g().doubleValue()) || Double.isNaN(interfaceC3027n2.g().doubleValue())) {
            return false;
        }
        return interfaceC3027n.g().equals(interfaceC3027n2.g());
    }
}
