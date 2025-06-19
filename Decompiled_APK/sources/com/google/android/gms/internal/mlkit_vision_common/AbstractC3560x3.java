package com.google.android.gms.internal.mlkit_vision_common;

import com.google.android.gms.internal.measurement.C2977d;
import com.google.android.gms.internal.measurement.C2982e;
import com.google.android.gms.internal.measurement.C2992g;
import com.google.android.gms.internal.measurement.C3012k;
import com.google.android.gms.internal.measurement.C3032o;
import com.google.android.gms.internal.measurement.C3039p1;
import com.google.android.gms.internal.measurement.C3042q;
import com.google.android.gms.internal.measurement.InterfaceC2975c2;
import com.google.android.gms.internal.measurement.InterfaceC3027n;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.x3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3560x3 {
    public static final /* synthetic */ int a = 0;

    public static InterfaceC3027n a(C3039p1 c3039p1) {
        if (c3039p1 == null) {
            return InterfaceC3027n.Q0;
        }
        int iV = c3039p1.v() - 1;
        if (iV == 1) {
            return c3039p1.u() ? new C3042q(c3039p1.p()) : InterfaceC3027n.X0;
        }
        if (iV == 2) {
            return c3039p1.t() ? new C2992g(Double.valueOf(c3039p1.n())) : new C2992g(null);
        }
        if (iV == 3) {
            return c3039p1.s() ? new C2982e(Boolean.valueOf(c3039p1.r())) : new C2982e(null);
        }
        if (iV != 4) {
            throw new IllegalArgumentException("Unknown type found. Cannot convert entity");
        }
        InterfaceC2975c2 interfaceC2975c2Q = c3039p1.q();
        ArrayList arrayList = new ArrayList();
        Iterator it2 = interfaceC2975c2Q.iterator();
        while (it2.hasNext()) {
            arrayList.add(a((C3039p1) it2.next()));
        }
        return new C3032o(arrayList, c3039p1.o());
    }

    public static InterfaceC3027n b(Object obj) {
        if (obj == null) {
            return InterfaceC3027n.R0;
        }
        if (obj instanceof String) {
            return new C3042q((String) obj);
        }
        if (obj instanceof Double) {
            return new C2992g((Double) obj);
        }
        if (obj instanceof Long) {
            return new C2992g(Double.valueOf(((Long) obj).doubleValue()));
        }
        if (obj instanceof Integer) {
            return new C2992g(Double.valueOf(((Integer) obj).doubleValue()));
        }
        if (obj instanceof Boolean) {
            return new C2982e((Boolean) obj);
        }
        if (!(obj instanceof Map)) {
            if (!(obj instanceof List)) {
                throw new IllegalArgumentException("Invalid value type");
            }
            C2977d c2977d = new C2977d();
            Iterator it2 = ((List) obj).iterator();
            while (it2.hasNext()) {
                c2977d.s(c2977d.e(), b(it2.next()));
            }
            return c2977d;
        }
        C3012k c3012k = new C3012k();
        Map map = (Map) obj;
        for (Object string : map.keySet()) {
            InterfaceC3027n interfaceC3027nB = b(map.get(string));
            if (string != null) {
                if (!(string instanceof String)) {
                    string = string.toString();
                }
                c3012k.b((String) string, interfaceC3027nB);
            }
        }
        return c3012k;
    }
}
