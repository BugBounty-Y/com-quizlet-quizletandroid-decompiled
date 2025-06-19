package com.google.android.gms.internal.ads;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.sB, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2605sB {
    public static final C1 a;

    static {
        C2305lB c2305lB = C2305lB.c;
        a = new C1(7);
    }

    public static void a(int i, List list, C2586rt c2586rt, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c2586rt.getClass();
        boolean z2 = list instanceof C1827aB;
        HA ha = (HA) c2586rt.b;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    ha.T(i, ((Long) list.get(i2)).longValue());
                    i2++;
                }
                return;
            }
            ha.Q(i, 2);
            int iD = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                iD += HA.D(((Long) list.get(i3)).longValue());
            }
            ha.S(iD);
            while (i2 < list.size()) {
                ha.U(((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        C1827aB c1827aB = (C1827aB) list;
        if (!z) {
            while (i2 < c1827aB.c) {
                ha.T(i, c1827aB.b(i2));
                i2++;
            }
            return;
        }
        ha.Q(i, 2);
        int iD2 = 0;
        for (int i4 = 0; i4 < c1827aB.c; i4++) {
            iD2 += HA.D(c1827aB.b(i4));
        }
        ha.S(iD2);
        while (i2 < c1827aB.c) {
            ha.U(c1827aB.b(i2));
            i2++;
        }
    }

    public static void b(int i, List list, C2586rt c2586rt, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c2586rt.getClass();
        boolean z2 = list instanceof PA;
        HA ha = (HA) c2586rt.b;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    ha.I(i, ((Integer) list.get(i2)).intValue());
                    i2++;
                }
                return;
            }
            ha.Q(i, 2);
            int i3 = 0;
            for (int i4 = 0; i4 < list.size(); i4++) {
                ((Integer) list.get(i4)).getClass();
                i3 += 4;
            }
            ha.S(i3);
            while (i2 < list.size()) {
                ha.J(((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        PA pa = (PA) list;
        if (!z) {
            while (i2 < pa.c) {
                ha.I(i, pa.b(i2));
                i2++;
            }
            return;
        }
        ha.Q(i, 2);
        int i5 = 0;
        for (int i6 = 0; i6 < pa.c; i6++) {
            pa.b(i6);
            i5 += 4;
        }
        ha.S(i5);
        while (i2 < pa.c) {
            ha.J(pa.b(i2));
            i2++;
        }
    }

    public static void c(int i, List list, C2586rt c2586rt, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c2586rt.getClass();
        boolean z2 = list instanceof C1827aB;
        HA ha = (HA) c2586rt.b;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    ha.K(i, ((Long) list.get(i2)).longValue());
                    i2++;
                }
                return;
            }
            ha.Q(i, 2);
            int i3 = 0;
            for (int i4 = 0; i4 < list.size(); i4++) {
                ((Long) list.get(i4)).getClass();
                i3 += 8;
            }
            ha.S(i3);
            while (i2 < list.size()) {
                ha.L(((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        C1827aB c1827aB = (C1827aB) list;
        if (!z) {
            while (i2 < c1827aB.c) {
                ha.K(i, c1827aB.b(i2));
                i2++;
            }
            return;
        }
        ha.Q(i, 2);
        int i5 = 0;
        for (int i6 = 0; i6 < c1827aB.c; i6++) {
            c1827aB.b(i6);
            i5 += 8;
        }
        ha.S(i5);
        while (i2 < c1827aB.c) {
            ha.L(c1827aB.b(i2));
            i2++;
        }
    }

    public static void d(int i, List list, C2586rt c2586rt, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c2586rt.getClass();
        boolean z2 = list instanceof PA;
        HA ha = (HA) c2586rt.b;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    int iIntValue = ((Integer) list.get(i2)).intValue();
                    ha.R(i, (iIntValue >> 31) ^ (iIntValue + iIntValue));
                    i2++;
                }
                return;
            }
            ha.Q(i, 2);
            int iC = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                int iIntValue2 = ((Integer) list.get(i3)).intValue();
                iC += HA.C((iIntValue2 >> 31) ^ (iIntValue2 + iIntValue2));
            }
            ha.S(iC);
            while (i2 < list.size()) {
                int iIntValue3 = ((Integer) list.get(i2)).intValue();
                ha.S((iIntValue3 >> 31) ^ (iIntValue3 + iIntValue3));
                i2++;
            }
            return;
        }
        PA pa = (PA) list;
        if (!z) {
            while (i2 < pa.c) {
                int iB = pa.b(i2);
                ha.R(i, (iB >> 31) ^ (iB + iB));
                i2++;
            }
            return;
        }
        ha.Q(i, 2);
        int iC2 = 0;
        for (int i4 = 0; i4 < pa.c; i4++) {
            int iB2 = pa.b(i4);
            iC2 += HA.C((iB2 >> 31) ^ (iB2 + iB2));
        }
        ha.S(iC2);
        while (i2 < pa.c) {
            int iB3 = pa.b(i2);
            ha.S((iB3 >> 31) ^ (iB3 + iB3));
            i2++;
        }
    }

    public static void e(int i, List list, C2586rt c2586rt, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c2586rt.getClass();
        boolean z2 = list instanceof C1827aB;
        HA ha = (HA) c2586rt.b;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    long jLongValue = ((Long) list.get(i2)).longValue();
                    ha.T(i, (jLongValue >> 63) ^ (jLongValue + jLongValue));
                    i2++;
                }
                return;
            }
            ha.Q(i, 2);
            int iD = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                long jLongValue2 = ((Long) list.get(i3)).longValue();
                iD += HA.D((jLongValue2 >> 63) ^ (jLongValue2 + jLongValue2));
            }
            ha.S(iD);
            while (i2 < list.size()) {
                long jLongValue3 = ((Long) list.get(i2)).longValue();
                ha.U((jLongValue3 >> 63) ^ (jLongValue3 + jLongValue3));
                i2++;
            }
            return;
        }
        C1827aB c1827aB = (C1827aB) list;
        if (!z) {
            while (i2 < c1827aB.c) {
                long jB = c1827aB.b(i2);
                ha.T(i, (jB >> 63) ^ (jB + jB));
                i2++;
            }
            return;
        }
        ha.Q(i, 2);
        int iD2 = 0;
        for (int i4 = 0; i4 < c1827aB.c; i4++) {
            long jB2 = c1827aB.b(i4);
            iD2 += HA.D((jB2 >> 63) ^ (jB2 + jB2));
        }
        ha.S(iD2);
        while (i2 < c1827aB.c) {
            long jB3 = c1827aB.b(i2);
            ha.U((jB3 >> 63) ^ (jB3 + jB3));
            i2++;
        }
    }

    public static void f(int i, List list, C2586rt c2586rt, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c2586rt.getClass();
        boolean z2 = list instanceof PA;
        HA ha = (HA) c2586rt.b;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    ha.R(i, ((Integer) list.get(i2)).intValue());
                    i2++;
                }
                return;
            }
            ha.Q(i, 2);
            int iC = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                iC += HA.C(((Integer) list.get(i3)).intValue());
            }
            ha.S(iC);
            while (i2 < list.size()) {
                ha.S(((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        PA pa = (PA) list;
        if (!z) {
            while (i2 < pa.c) {
                ha.R(i, pa.b(i2));
                i2++;
            }
            return;
        }
        ha.Q(i, 2);
        int iC2 = 0;
        for (int i4 = 0; i4 < pa.c; i4++) {
            iC2 += HA.C(pa.b(i4));
        }
        ha.S(iC2);
        while (i2 < pa.c) {
            ha.S(pa.b(i2));
            i2++;
        }
    }

    public static void g(int i, List list, C2586rt c2586rt, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c2586rt.getClass();
        boolean z2 = list instanceof C1827aB;
        HA ha = (HA) c2586rt.b;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    ha.T(i, ((Long) list.get(i2)).longValue());
                    i2++;
                }
                return;
            }
            ha.Q(i, 2);
            int iD = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                iD += HA.D(((Long) list.get(i3)).longValue());
            }
            ha.S(iD);
            while (i2 < list.size()) {
                ha.U(((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        C1827aB c1827aB = (C1827aB) list;
        if (!z) {
            while (i2 < c1827aB.c) {
                ha.T(i, c1827aB.b(i2));
                i2++;
            }
            return;
        }
        ha.Q(i, 2);
        int iD2 = 0;
        for (int i4 = 0; i4 < c1827aB.c; i4++) {
            iD2 += HA.D(c1827aB.b(i4));
        }
        ha.S(iD2);
        while (i2 < c1827aB.c) {
            ha.U(c1827aB.b(i2));
            i2++;
        }
    }

    public static boolean h(Object obj, Object obj2) {
        if (obj != obj2) {
            return obj != null && obj.equals(obj2);
        }
        return true;
    }

    public static int i(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof PA)) {
            int iD = 0;
            while (i < size) {
                iD += HA.D(((Integer) list.get(i)).intValue());
                i++;
            }
            return iD;
        }
        PA pa = (PA) list;
        int iD2 = 0;
        while (i < size) {
            iD2 += HA.D(pa.b(i));
            i++;
        }
        return iD2;
    }

    public static int j(int i, List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return (HA.C(i << 3) + 4) * size;
    }

    public static int k(int i, List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return (HA.C(i << 3) + 8) * size;
    }

    public static int l(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof PA)) {
            int iD = 0;
            while (i < size) {
                iD += HA.D(((Integer) list.get(i)).intValue());
                i++;
            }
            return iD;
        }
        PA pa = (PA) list;
        int iD2 = 0;
        while (i < size) {
            iD2 += HA.D(pa.b(i));
            i++;
        }
        return iD2;
    }

    public static int m(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof C1827aB)) {
            int iD = 0;
            while (i < size) {
                iD += HA.D(((Long) list.get(i)).longValue());
                i++;
            }
            return iD;
        }
        C1827aB c1827aB = (C1827aB) list;
        int iD2 = 0;
        while (i < size) {
            iD2 += HA.D(c1827aB.b(i));
            i++;
        }
        return iD2;
    }

    public static int n(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof PA)) {
            int iC = 0;
            while (i < size) {
                int iIntValue = ((Integer) list.get(i)).intValue();
                iC += HA.C((iIntValue >> 31) ^ (iIntValue + iIntValue));
                i++;
            }
            return iC;
        }
        PA pa = (PA) list;
        int iC2 = 0;
        while (i < size) {
            int iB = pa.b(i);
            iC2 += HA.C((iB >> 31) ^ (iB + iB));
            i++;
        }
        return iC2;
    }

    public static int o(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof C1827aB)) {
            int iD = 0;
            while (i < size) {
                long jLongValue = ((Long) list.get(i)).longValue();
                iD += HA.D((jLongValue >> 63) ^ (jLongValue + jLongValue));
                i++;
            }
            return iD;
        }
        C1827aB c1827aB = (C1827aB) list;
        int iD2 = 0;
        while (i < size) {
            long jB = c1827aB.b(i);
            iD2 += HA.D((jB >> 63) ^ (jB + jB));
            i++;
        }
        return iD2;
    }

    public static int p(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof PA)) {
            int iC = 0;
            while (i < size) {
                iC += HA.C(((Integer) list.get(i)).intValue());
                i++;
            }
            return iC;
        }
        PA pa = (PA) list;
        int iC2 = 0;
        while (i < size) {
            iC2 += HA.C(pa.b(i));
            i++;
        }
        return iC2;
    }

    public static int q(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof C1827aB)) {
            int iD = 0;
            while (i < size) {
                iD += HA.D(((Long) list.get(i)).longValue());
                i++;
            }
            return iD;
        }
        C1827aB c1827aB = (C1827aB) list;
        int iD2 = 0;
        while (i < size) {
            iD2 += HA.D(c1827aB.b(i));
            i++;
        }
        return iD2;
    }

    public static Object r(Object obj, int i, VA va, RA ra, Object obj2, C1 c1) {
        if (ra == null) {
            return obj2;
        }
        if (va == null) {
            Iterator it2 = va.iterator();
            while (it2.hasNext()) {
                int iIntValue = ((Integer) it2.next()).intValue();
                if (!ra.zza(iIntValue)) {
                    if (obj2 == null) {
                        c1.getClass();
                        obj2 = C1.r(obj);
                    }
                    c1.getClass();
                    ((C2691uB) obj2).c(i << 3, Long.valueOf(iIntValue));
                    it2.remove();
                }
            }
            return obj2;
        }
        int size = va.size();
        int i2 = 0;
        for (int i3 = 0; i3 < size; i3++) {
            Integer num = (Integer) va.get(i3);
            int iIntValue2 = num.intValue();
            if (ra.zza(iIntValue2)) {
                if (i3 != i2) {
                    va.set(i2, num);
                }
                i2++;
            } else {
                if (obj2 == null) {
                    c1.getClass();
                    obj2 = C1.r(obj);
                }
                c1.getClass();
                ((C2691uB) obj2).c(i << 3, Long.valueOf(iIntValue2));
            }
        }
        if (i2 != size) {
            va.subList(i2, size).clear();
        }
        return obj2;
    }

    public static void s(Object obj, Object obj2) {
        OA oa = (OA) obj;
        C2691uB c2691uB = oa.zzt;
        C2691uB c2691uB2 = ((OA) obj2).zzt;
        C2691uB c2691uB3 = C2691uB.f;
        if (!c2691uB3.equals(c2691uB2)) {
            if (c2691uB3.equals(c2691uB)) {
                int i = c2691uB.a + c2691uB2.a;
                int[] iArrCopyOf = Arrays.copyOf(c2691uB.b, i);
                System.arraycopy(c2691uB2.b, 0, iArrCopyOf, c2691uB.a, c2691uB2.a);
                Object[] objArrCopyOf = Arrays.copyOf(c2691uB.c, i);
                System.arraycopy(c2691uB2.c, 0, objArrCopyOf, c2691uB.a, c2691uB2.a);
                c2691uB = new C2691uB(i, iArrCopyOf, objArrCopyOf, true);
            } else {
                c2691uB.getClass();
                if (!c2691uB2.equals(c2691uB3)) {
                    if (!c2691uB.e) {
                        throw new UnsupportedOperationException();
                    }
                    int i2 = c2691uB.a + c2691uB2.a;
                    c2691uB.e(i2);
                    System.arraycopy(c2691uB2.b, 0, c2691uB.b, c2691uB.a, c2691uB2.a);
                    System.arraycopy(c2691uB2.c, 0, c2691uB.c, c2691uB.a, c2691uB2.a);
                    c2691uB.a = i2;
                }
            }
        }
        oa.zzt = c2691uB;
    }

    public static void t(int i, List list, C2586rt c2586rt, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        HA ha = (HA) c2586rt.b;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                ha.G(i, ((Boolean) list.get(i2)).booleanValue());
                i2++;
            }
            return;
        }
        ha.Q(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Boolean) list.get(i4)).getClass();
            i3++;
        }
        ha.S(i3);
        while (i2 < list.size()) {
            ha.F(((Boolean) list.get(i2)).booleanValue() ? (byte) 1 : (byte) 0);
            i2++;
        }
    }

    public static void u(int i, List list, C2586rt c2586rt, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        HA ha = (HA) c2586rt.b;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                ha.K(i, Double.doubleToRawLongBits(((Double) list.get(i2)).doubleValue()));
                i2++;
            }
            return;
        }
        ha.Q(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Double) list.get(i4)).getClass();
            i3 += 8;
        }
        ha.S(i3);
        while (i2 < list.size()) {
            ha.L(Double.doubleToRawLongBits(((Double) list.get(i2)).doubleValue()));
            i2++;
        }
    }

    public static void v(int i, List list, C2586rt c2586rt, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c2586rt.getClass();
        boolean z2 = list instanceof PA;
        HA ha = (HA) c2586rt.b;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    ha.M(i, ((Integer) list.get(i2)).intValue());
                    i2++;
                }
                return;
            }
            ha.Q(i, 2);
            int iD = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                iD += HA.D(((Integer) list.get(i3)).intValue());
            }
            ha.S(iD);
            while (i2 < list.size()) {
                ha.N(((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        PA pa = (PA) list;
        if (!z) {
            while (i2 < pa.c) {
                ha.M(i, pa.b(i2));
                i2++;
            }
            return;
        }
        ha.Q(i, 2);
        int iD2 = 0;
        for (int i4 = 0; i4 < pa.c; i4++) {
            iD2 += HA.D(pa.b(i4));
        }
        ha.S(iD2);
        while (i2 < pa.c) {
            ha.N(pa.b(i2));
            i2++;
        }
    }

    public static void w(int i, List list, C2586rt c2586rt, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c2586rt.getClass();
        boolean z2 = list instanceof PA;
        HA ha = (HA) c2586rt.b;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    ha.I(i, ((Integer) list.get(i2)).intValue());
                    i2++;
                }
                return;
            }
            ha.Q(i, 2);
            int i3 = 0;
            for (int i4 = 0; i4 < list.size(); i4++) {
                ((Integer) list.get(i4)).getClass();
                i3 += 4;
            }
            ha.S(i3);
            while (i2 < list.size()) {
                ha.J(((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        PA pa = (PA) list;
        if (!z) {
            while (i2 < pa.c) {
                ha.I(i, pa.b(i2));
                i2++;
            }
            return;
        }
        ha.Q(i, 2);
        int i5 = 0;
        for (int i6 = 0; i6 < pa.c; i6++) {
            pa.b(i6);
            i5 += 4;
        }
        ha.S(i5);
        while (i2 < pa.c) {
            ha.J(pa.b(i2));
            i2++;
        }
    }

    public static void x(int i, List list, C2586rt c2586rt, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c2586rt.getClass();
        boolean z2 = list instanceof C1827aB;
        HA ha = (HA) c2586rt.b;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    ha.K(i, ((Long) list.get(i2)).longValue());
                    i2++;
                }
                return;
            }
            ha.Q(i, 2);
            int i3 = 0;
            for (int i4 = 0; i4 < list.size(); i4++) {
                ((Long) list.get(i4)).getClass();
                i3 += 8;
            }
            ha.S(i3);
            while (i2 < list.size()) {
                ha.L(((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        C1827aB c1827aB = (C1827aB) list;
        if (!z) {
            while (i2 < c1827aB.c) {
                ha.K(i, c1827aB.b(i2));
                i2++;
            }
            return;
        }
        ha.Q(i, 2);
        int i5 = 0;
        for (int i6 = 0; i6 < c1827aB.c; i6++) {
            c1827aB.b(i6);
            i5 += 8;
        }
        ha.S(i5);
        while (i2 < c1827aB.c) {
            ha.L(c1827aB.b(i2));
            i2++;
        }
    }

    public static void y(int i, List list, C2586rt c2586rt, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        HA ha = (HA) c2586rt.b;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                ha.I(i, Float.floatToRawIntBits(((Float) list.get(i2)).floatValue()));
                i2++;
            }
            return;
        }
        ha.Q(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Float) list.get(i4)).getClass();
            i3 += 4;
        }
        ha.S(i3);
        while (i2 < list.size()) {
            ha.J(Float.floatToRawIntBits(((Float) list.get(i2)).floatValue()));
            i2++;
        }
    }

    public static void z(int i, List list, C2586rt c2586rt, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c2586rt.getClass();
        boolean z2 = list instanceof PA;
        HA ha = (HA) c2586rt.b;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    ha.M(i, ((Integer) list.get(i2)).intValue());
                    i2++;
                }
                return;
            }
            ha.Q(i, 2);
            int iD = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                iD += HA.D(((Integer) list.get(i3)).intValue());
            }
            ha.S(iD);
            while (i2 < list.size()) {
                ha.N(((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        PA pa = (PA) list;
        if (!z) {
            while (i2 < pa.c) {
                ha.M(i, pa.b(i2));
                i2++;
            }
            return;
        }
        ha.Q(i, 2);
        int iD2 = 0;
        for (int i4 = 0; i4 < pa.c; i4++) {
            iD2 += HA.D(pa.b(i4));
        }
        ha.S(iD2);
        while (i2 < pa.c) {
            ha.N(pa.b(i2));
            i2++;
        }
    }
}
