package com.google.android.gms.measurement.internal;

import androidx.collection.C0205c;
import androidx.collection.C0208f;
import com.google.android.gms.internal.measurement.C2981d3;
import com.google.android.gms.internal.measurement.C2984e1;
import com.google.android.gms.internal.measurement.C2989f1;
import com.google.android.gms.internal.measurement.C2994g1;
import com.google.android.gms.internal.measurement.C2999h1;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes2.dex */
public final class y1 {
    public final String a;
    public final boolean b;
    public final C2989f1 c;
    public final BitSet d;
    public final BitSet e;
    public final C0208f f;
    public final C0208f g;
    public final /* synthetic */ C3860c h;

    public y1(C3860c c3860c, String str) {
        this.h = c3860c;
        this.a = str;
        this.b = true;
        this.d = new BitSet();
        this.e = new BitSet();
        this.f = new C0208f(0);
        this.g = new C0208f(0);
    }

    public final com.google.android.gms.internal.measurement.Q0 a(int i) {
        ArrayList arrayList;
        List list;
        com.google.android.gms.internal.measurement.P0 p0O = com.google.android.gms.internal.measurement.Q0.o();
        p0O.h();
        com.google.android.gms.internal.measurement.Q0.r((com.google.android.gms.internal.measurement.Q0) p0O.b, i);
        p0O.h();
        com.google.android.gms.internal.measurement.Q0.t((com.google.android.gms.internal.measurement.Q0) p0O.b, this.b);
        C2989f1 c2989f1 = this.c;
        if (c2989f1 != null) {
            p0O.h();
            com.google.android.gms.internal.measurement.Q0.u((com.google.android.gms.internal.measurement.Q0) p0O.b, c2989f1);
        }
        C2984e1 c2984e1R = C2989f1.r();
        ArrayList arrayListC0 = M.C0(this.d);
        c2984e1R.h();
        C2989f1.y((C2989f1) c2984e1R.b, arrayListC0);
        ArrayList arrayListC02 = M.C0(this.e);
        c2984e1R.h();
        C2989f1.A((C2989f1) c2984e1R.b, arrayListC02);
        C0208f c0208f = this.f;
        if (c0208f == null) {
            arrayList = null;
        } else {
            ArrayList arrayList2 = new ArrayList(c0208f.c);
            Iterator it2 = ((C0205c) c0208f.keySet()).iterator();
            while (it2.hasNext()) {
                Integer num = (Integer) it2.next();
                int iIntValue = num.intValue();
                Long l = (Long) c0208f.get(num);
                if (l != null) {
                    com.google.android.gms.internal.measurement.R0 r0P = com.google.android.gms.internal.measurement.S0.p();
                    r0P.h();
                    com.google.android.gms.internal.measurement.S0.r((com.google.android.gms.internal.measurement.S0) r0P.b, iIntValue);
                    long jLongValue = l.longValue();
                    r0P.h();
                    com.google.android.gms.internal.measurement.S0.q((com.google.android.gms.internal.measurement.S0) r0P.b, jLongValue);
                    arrayList2.add((com.google.android.gms.internal.measurement.S0) r0P.f());
                }
            }
            arrayList = arrayList2;
        }
        if (arrayList != null) {
            c2984e1R.h();
            C2989f1.x((C2989f1) c2984e1R.b, arrayList);
        }
        C0208f c0208f2 = this.g;
        if (c0208f2 == null) {
            list = Collections.EMPTY_LIST;
        } else {
            ArrayList arrayList3 = new ArrayList(c0208f2.c);
            Iterator it3 = ((C0205c) c0208f2.keySet()).iterator();
            while (it3.hasNext()) {
                Integer num2 = (Integer) it3.next();
                C2994g1 c2994g1Q = C2999h1.q();
                int iIntValue2 = num2.intValue();
                c2994g1Q.h();
                C2999h1.t((C2999h1) c2994g1Q.b, iIntValue2);
                List list2 = (List) c0208f2.get(num2);
                if (list2 != null) {
                    Collections.sort(list2);
                    c2994g1Q.h();
                    C2999h1.s((C2999h1) c2994g1Q.b, list2);
                }
                arrayList3.add((C2999h1) c2994g1Q.f());
            }
            list = arrayList3;
        }
        c2984e1R.h();
        C2989f1.z((C2989f1) c2984e1R.b, list);
        p0O.h();
        com.google.android.gms.internal.measurement.Q0.s((com.google.android.gms.internal.measurement.Q0) p0O.b, (C2989f1) c2984e1R.f());
        return (com.google.android.gms.internal.measurement.Q0) p0O.f();
    }

    public final void b(androidx.navigation.C c) {
        int iC = c.c();
        if (((Boolean) c.c) != null) {
            this.e.set(iC, true);
        }
        Boolean bool = (Boolean) c.d;
        if (bool != null) {
            this.d.set(iC, bool.booleanValue());
        }
        if (((Long) c.e) != null) {
            Integer numValueOf = Integer.valueOf(iC);
            C0208f c0208f = this.f;
            Long l = (Long) c0208f.get(numValueOf);
            long jLongValue = ((Long) c.e).longValue() / 1000;
            if (l == null || jLongValue > l.longValue()) {
                c0208f.put(numValueOf, Long.valueOf(jLongValue));
            }
        }
        if (((Long) c.f) != null) {
            C0208f c0208f2 = this.g;
            Integer numValueOf2 = Integer.valueOf(iC);
            List arrayList = (List) c0208f2.get(numValueOf2);
            if (arrayList == null) {
                arrayList = new ArrayList();
                c0208f2.put(numValueOf2, arrayList);
            }
            if (c.e()) {
                arrayList.clear();
            }
            C2981d3.a();
            Y y = (Y) this.h.b;
            C3864e c3864e = y.g;
            C3891s c3891s = AbstractC3893t.E0;
            String str = this.a;
            if (c3864e.f0(str, c3891s) && c.d()) {
                arrayList.clear();
            }
            C2981d3.a();
            if (!y.g.f0(str, c3891s)) {
                arrayList.add(Long.valueOf(((Long) c.f).longValue() / 1000));
                return;
            }
            Long lValueOf = Long.valueOf(((Long) c.f).longValue() / 1000);
            if (arrayList.contains(lValueOf)) {
                return;
            }
            arrayList.add(lValueOf);
        }
    }

    public y1(C3860c c3860c, String str, C2989f1 c2989f1, BitSet bitSet, BitSet bitSet2, C0208f c0208f, C0208f c0208f2) {
        this.h = c3860c;
        this.a = str;
        this.d = bitSet;
        this.e = bitSet2;
        this.f = c0208f;
        this.g = new C0208f(0);
        Iterator it2 = ((C0205c) c0208f2.keySet()).iterator();
        while (it2.hasNext()) {
            Integer num = (Integer) it2.next();
            ArrayList arrayList = new ArrayList();
            arrayList.add((Long) c0208f2.get(num));
            this.g.put(num, arrayList);
        }
        this.b = false;
        this.c = c2989f1;
    }
}
