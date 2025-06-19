package com.google.android.gms.internal.measurement;

import java.util.Arrays;
import java.util.List;

/* renamed from: com.google.android.gms.internal.measurement.w2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3074w2 {
    public static final U1 a;

    static {
        C3054s2 c3054s2 = C3054s2.c;
        a = new U1(6);
    }

    public static void a(int i, List list, C3005i2 c3005i2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c3005i2.getClass();
        boolean z2 = list instanceof X1;
        P1 p1 = (P1) c3005i2.a;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    int iIntValue = ((Integer) list.get(i2)).intValue();
                    p1.l(i, (iIntValue >> 31) ^ (iIntValue + iIntValue));
                    i2++;
                }
                return;
            }
            p1.k(i, 2);
            int iQ = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                int iIntValue2 = ((Integer) list.get(i3)).intValue();
                iQ += P1.q((iIntValue2 >> 31) ^ (iIntValue2 + iIntValue2));
            }
            p1.m(iQ);
            while (i2 < list.size()) {
                int iIntValue3 = ((Integer) list.get(i2)).intValue();
                p1.m((iIntValue3 >> 31) ^ (iIntValue3 + iIntValue3));
                i2++;
            }
            return;
        }
        X1 x1 = (X1) list;
        if (!z) {
            while (i2 < x1.c) {
                int iB = x1.b(i2);
                p1.l(i, (iB >> 31) ^ (iB + iB));
                i2++;
            }
            return;
        }
        p1.k(i, 2);
        int iQ2 = 0;
        for (int i4 = 0; i4 < x1.c; i4++) {
            int iB2 = x1.b(i4);
            iQ2 += P1.q((iB2 >> 31) ^ (iB2 + iB2));
        }
        p1.m(iQ2);
        while (i2 < x1.c) {
            int iB3 = x1.b(i2);
            p1.m((iB3 >> 31) ^ (iB3 + iB3));
            i2++;
        }
    }

    public static void b(int i, List list, C3005i2 c3005i2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c3005i2.getClass();
        boolean z2 = list instanceof C3000h2;
        P1 p1 = (P1) c3005i2.a;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    long jLongValue = ((Long) list.get(i2)).longValue();
                    p1.n(i, (jLongValue >> 63) ^ (jLongValue + jLongValue));
                    i2++;
                }
                return;
            }
            p1.k(i, 2);
            int iA = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                long jLongValue2 = ((Long) list.get(i3)).longValue();
                iA += P1.a((jLongValue2 >> 63) ^ (jLongValue2 + jLongValue2));
            }
            p1.m(iA);
            while (i2 < list.size()) {
                long jLongValue3 = ((Long) list.get(i2)).longValue();
                p1.o((jLongValue3 >> 63) ^ (jLongValue3 + jLongValue3));
                i2++;
            }
            return;
        }
        C3000h2 c3000h2 = (C3000h2) list;
        if (!z) {
            while (i2 < c3000h2.c) {
                long jB = c3000h2.b(i2);
                p1.n(i, (jB >> 63) ^ (jB + jB));
                i2++;
            }
            return;
        }
        p1.k(i, 2);
        int iA2 = 0;
        for (int i4 = 0; i4 < c3000h2.c; i4++) {
            long jB2 = c3000h2.b(i4);
            iA2 += P1.a((jB2 >> 63) ^ (jB2 + jB2));
        }
        p1.m(iA2);
        while (i2 < c3000h2.c) {
            long jB3 = c3000h2.b(i2);
            p1.o((jB3 >> 63) ^ (jB3 + jB3));
            i2++;
        }
    }

    public static void c(int i, List list, C3005i2 c3005i2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c3005i2.getClass();
        boolean z2 = list instanceof X1;
        P1 p1 = (P1) c3005i2.a;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    p1.l(i, ((Integer) list.get(i2)).intValue());
                    i2++;
                }
                return;
            }
            p1.k(i, 2);
            int iQ = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                iQ += P1.q(((Integer) list.get(i3)).intValue());
            }
            p1.m(iQ);
            while (i2 < list.size()) {
                p1.m(((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        X1 x1 = (X1) list;
        if (!z) {
            while (i2 < x1.c) {
                p1.l(i, x1.b(i2));
                i2++;
            }
            return;
        }
        p1.k(i, 2);
        int iQ2 = 0;
        for (int i4 = 0; i4 < x1.c; i4++) {
            iQ2 += P1.q(x1.b(i4));
        }
        p1.m(iQ2);
        while (i2 < x1.c) {
            p1.m(x1.b(i2));
            i2++;
        }
    }

    public static void d(int i, List list, C3005i2 c3005i2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c3005i2.getClass();
        boolean z2 = list instanceof C3000h2;
        P1 p1 = (P1) c3005i2.a;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    p1.n(i, ((Long) list.get(i2)).longValue());
                    i2++;
                }
                return;
            }
            p1.k(i, 2);
            int iA = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                iA += P1.a(((Long) list.get(i3)).longValue());
            }
            p1.m(iA);
            while (i2 < list.size()) {
                p1.o(((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        C3000h2 c3000h2 = (C3000h2) list;
        if (!z) {
            while (i2 < c3000h2.c) {
                p1.n(i, c3000h2.b(i2));
                i2++;
            }
            return;
        }
        p1.k(i, 2);
        int iA2 = 0;
        for (int i4 = 0; i4 < c3000h2.c; i4++) {
            iA2 += P1.a(c3000h2.b(i4));
        }
        p1.m(iA2);
        while (i2 < c3000h2.c) {
            p1.o(c3000h2.b(i2));
            i2++;
        }
    }

    public static boolean e(Object obj, Object obj2) {
        if (obj != obj2) {
            return obj != null && obj.equals(obj2);
        }
        return true;
    }

    public static int f(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof X1)) {
            int iA = 0;
            while (i < size) {
                iA += P1.a(((Integer) list.get(i)).intValue());
                i++;
            }
            return iA;
        }
        X1 x1 = (X1) list;
        int iA2 = 0;
        while (i < size) {
            iA2 += P1.a(x1.b(i));
            i++;
        }
        return iA2;
    }

    public static int g(int i, List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return (P1.q(i << 3) + 4) * size;
    }

    public static int h(int i, List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return (P1.q(i << 3) + 8) * size;
    }

    public static int i(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof X1)) {
            int iA = 0;
            while (i < size) {
                iA += P1.a(((Integer) list.get(i)).intValue());
                i++;
            }
            return iA;
        }
        X1 x1 = (X1) list;
        int iA2 = 0;
        while (i < size) {
            iA2 += P1.a(x1.b(i));
            i++;
        }
        return iA2;
    }

    public static int j(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof C3000h2)) {
            int iA = 0;
            while (i < size) {
                iA += P1.a(((Long) list.get(i)).longValue());
                i++;
            }
            return iA;
        }
        C3000h2 c3000h2 = (C3000h2) list;
        int iA2 = 0;
        while (i < size) {
            iA2 += P1.a(c3000h2.b(i));
            i++;
        }
        return iA2;
    }

    public static int k(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof X1)) {
            int iQ = 0;
            while (i < size) {
                int iIntValue = ((Integer) list.get(i)).intValue();
                iQ += P1.q((iIntValue >> 31) ^ (iIntValue + iIntValue));
                i++;
            }
            return iQ;
        }
        X1 x1 = (X1) list;
        int iQ2 = 0;
        while (i < size) {
            int iB = x1.b(i);
            iQ2 += P1.q((iB >> 31) ^ (iB + iB));
            i++;
        }
        return iQ2;
    }

    public static int l(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof C3000h2)) {
            int iA = 0;
            while (i < size) {
                long jLongValue = ((Long) list.get(i)).longValue();
                iA += P1.a((jLongValue >> 63) ^ (jLongValue + jLongValue));
                i++;
            }
            return iA;
        }
        C3000h2 c3000h2 = (C3000h2) list;
        int iA2 = 0;
        while (i < size) {
            long jB = c3000h2.b(i);
            iA2 += P1.a((jB >> 63) ^ (jB + jB));
            i++;
        }
        return iA2;
    }

    public static int m(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof X1)) {
            int iQ = 0;
            while (i < size) {
                iQ += P1.q(((Integer) list.get(i)).intValue());
                i++;
            }
            return iQ;
        }
        X1 x1 = (X1) list;
        int iQ2 = 0;
        while (i < size) {
            iQ2 += P1.q(x1.b(i));
            i++;
        }
        return iQ2;
    }

    public static int n(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof C3000h2)) {
            int iA = 0;
            while (i < size) {
                iA += P1.a(((Long) list.get(i)).longValue());
                i++;
            }
            return iA;
        }
        C3000h2 c3000h2 = (C3000h2) list;
        int iA2 = 0;
        while (i < size) {
            iA2 += P1.a(c3000h2.b(i));
            i++;
        }
        return iA2;
    }

    public static Object o(Object obj, int i, Object obj2, int i2) {
        Object obj3 = obj2;
        if (obj2 == null) {
            W1 w1 = (W1) obj;
            C3079x2 c3079x2 = w1.zzc;
            obj3 = c3079x2;
            if (c3079x2 == C3079x2.f) {
                C3079x2 c3079x2B = C3079x2.b();
                w1.zzc = c3079x2B;
                obj3 = c3079x2B;
            }
        }
        ((C3079x2) obj3).c(i << 3, Long.valueOf(i2));
        return obj3;
    }

    public static void p(Object obj, Object obj2) {
        W1 w1 = (W1) obj;
        C3079x2 c3079x2 = w1.zzc;
        C3079x2 c3079x22 = ((W1) obj2).zzc;
        C3079x2 c3079x23 = C3079x2.f;
        if (!c3079x23.equals(c3079x22)) {
            if (c3079x23.equals(c3079x2)) {
                int i = c3079x2.a + c3079x22.a;
                int[] iArrCopyOf = Arrays.copyOf(c3079x2.b, i);
                System.arraycopy(c3079x22.b, 0, iArrCopyOf, c3079x2.a, c3079x22.a);
                Object[] objArrCopyOf = Arrays.copyOf(c3079x2.c, i);
                System.arraycopy(c3079x22.c, 0, objArrCopyOf, c3079x2.a, c3079x22.a);
                c3079x2 = new C3079x2(i, iArrCopyOf, objArrCopyOf, true);
            } else {
                c3079x2.getClass();
                if (!c3079x22.equals(c3079x23)) {
                    if (!c3079x2.e) {
                        throw new UnsupportedOperationException();
                    }
                    int i2 = c3079x2.a + c3079x22.a;
                    c3079x2.e(i2);
                    System.arraycopy(c3079x22.b, 0, c3079x2.b, c3079x2.a, c3079x22.a);
                    System.arraycopy(c3079x22.c, 0, c3079x2.c, c3079x2.a, c3079x22.a);
                    c3079x2.a = i2;
                }
            }
        }
        w1.zzc = c3079x2;
    }

    public static void q(int i, List list, C3005i2 c3005i2, boolean z) {
        IndexOutOfBoundsException indexOutOfBoundsException;
        IndexOutOfBoundsException indexOutOfBoundsException2;
        if (list == null || list.isEmpty()) {
            return;
        }
        P1 p1 = (P1) c3005i2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                byte bBooleanValue = ((Boolean) list.get(i2)).booleanValue();
                p1.m(i << 3);
                int i3 = p1.e;
                try {
                    int i4 = i3 + 1;
                    try {
                        p1.c[i3] = bBooleanValue;
                        p1.e = i4;
                        i2++;
                    } catch (IndexOutOfBoundsException e) {
                        indexOutOfBoundsException = e;
                        i3 = i4;
                        throw new zzli(i3, p1.d, 1, indexOutOfBoundsException);
                    }
                } catch (IndexOutOfBoundsException e2) {
                    indexOutOfBoundsException = e2;
                }
            }
            return;
        }
        p1.k(i, 2);
        int i5 = 0;
        for (int i6 = 0; i6 < list.size(); i6++) {
            ((Boolean) list.get(i6)).getClass();
            i5++;
        }
        p1.m(i5);
        while (i2 < list.size()) {
            byte bBooleanValue2 = ((Boolean) list.get(i2)).booleanValue();
            int i7 = p1.e;
            try {
                int i8 = i7 + 1;
                try {
                    p1.c[i7] = bBooleanValue2;
                    p1.e = i8;
                    i2++;
                } catch (IndexOutOfBoundsException e3) {
                    indexOutOfBoundsException2 = e3;
                    i7 = i8;
                    throw new zzli(i7, p1.d, 1, indexOutOfBoundsException2);
                }
            } catch (IndexOutOfBoundsException e4) {
                indexOutOfBoundsException2 = e4;
            }
        }
    }

    public static void r(int i, List list, C3005i2 c3005i2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        P1 p1 = (P1) c3005i2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                p1.f(i, Double.doubleToRawLongBits(((Double) list.get(i2)).doubleValue()));
                i2++;
            }
            return;
        }
        p1.k(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Double) list.get(i4)).getClass();
            i3 += 8;
        }
        p1.m(i3);
        while (i2 < list.size()) {
            p1.g(Double.doubleToRawLongBits(((Double) list.get(i2)).doubleValue()));
            i2++;
        }
    }

    public static void s(int i, List list, C3005i2 c3005i2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c3005i2.getClass();
        boolean z2 = list instanceof X1;
        P1 p1 = (P1) c3005i2.a;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    p1.h(i, ((Integer) list.get(i2)).intValue());
                    i2++;
                }
                return;
            }
            p1.k(i, 2);
            int iA = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                iA += P1.a(((Integer) list.get(i3)).intValue());
            }
            p1.m(iA);
            while (i2 < list.size()) {
                p1.i(((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        X1 x1 = (X1) list;
        if (!z) {
            while (i2 < x1.c) {
                p1.h(i, x1.b(i2));
                i2++;
            }
            return;
        }
        p1.k(i, 2);
        int iA2 = 0;
        for (int i4 = 0; i4 < x1.c; i4++) {
            iA2 += P1.a(x1.b(i4));
        }
        p1.m(iA2);
        while (i2 < x1.c) {
            p1.i(x1.b(i2));
            i2++;
        }
    }

    public static void t(int i, List list, C3005i2 c3005i2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c3005i2.getClass();
        boolean z2 = list instanceof X1;
        P1 p1 = (P1) c3005i2.a;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    p1.d(i, ((Integer) list.get(i2)).intValue());
                    i2++;
                }
                return;
            }
            p1.k(i, 2);
            int i3 = 0;
            for (int i4 = 0; i4 < list.size(); i4++) {
                ((Integer) list.get(i4)).getClass();
                i3 += 4;
            }
            p1.m(i3);
            while (i2 < list.size()) {
                p1.e(((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        X1 x1 = (X1) list;
        if (!z) {
            while (i2 < x1.c) {
                p1.d(i, x1.b(i2));
                i2++;
            }
            return;
        }
        p1.k(i, 2);
        int i5 = 0;
        for (int i6 = 0; i6 < x1.c; i6++) {
            x1.b(i6);
            i5 += 4;
        }
        p1.m(i5);
        while (i2 < x1.c) {
            p1.e(x1.b(i2));
            i2++;
        }
    }

    public static void u(int i, List list, C3005i2 c3005i2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c3005i2.getClass();
        boolean z2 = list instanceof C3000h2;
        P1 p1 = (P1) c3005i2.a;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    p1.f(i, ((Long) list.get(i2)).longValue());
                    i2++;
                }
                return;
            }
            p1.k(i, 2);
            int i3 = 0;
            for (int i4 = 0; i4 < list.size(); i4++) {
                ((Long) list.get(i4)).getClass();
                i3 += 8;
            }
            p1.m(i3);
            while (i2 < list.size()) {
                p1.g(((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        C3000h2 c3000h2 = (C3000h2) list;
        if (!z) {
            while (i2 < c3000h2.c) {
                p1.f(i, c3000h2.b(i2));
                i2++;
            }
            return;
        }
        p1.k(i, 2);
        int i5 = 0;
        for (int i6 = 0; i6 < c3000h2.c; i6++) {
            c3000h2.b(i6);
            i5 += 8;
        }
        p1.m(i5);
        while (i2 < c3000h2.c) {
            p1.g(c3000h2.b(i2));
            i2++;
        }
    }

    public static void v(int i, List list, C3005i2 c3005i2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        P1 p1 = (P1) c3005i2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                p1.d(i, Float.floatToRawIntBits(((Float) list.get(i2)).floatValue()));
                i2++;
            }
            return;
        }
        p1.k(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Float) list.get(i4)).getClass();
            i3 += 4;
        }
        p1.m(i3);
        while (i2 < list.size()) {
            p1.e(Float.floatToRawIntBits(((Float) list.get(i2)).floatValue()));
            i2++;
        }
    }

    public static void w(int i, List list, C3005i2 c3005i2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c3005i2.getClass();
        boolean z2 = list instanceof X1;
        P1 p1 = (P1) c3005i2.a;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    p1.h(i, ((Integer) list.get(i2)).intValue());
                    i2++;
                }
                return;
            }
            p1.k(i, 2);
            int iA = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                iA += P1.a(((Integer) list.get(i3)).intValue());
            }
            p1.m(iA);
            while (i2 < list.size()) {
                p1.i(((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        X1 x1 = (X1) list;
        if (!z) {
            while (i2 < x1.c) {
                p1.h(i, x1.b(i2));
                i2++;
            }
            return;
        }
        p1.k(i, 2);
        int iA2 = 0;
        for (int i4 = 0; i4 < x1.c; i4++) {
            iA2 += P1.a(x1.b(i4));
        }
        p1.m(iA2);
        while (i2 < x1.c) {
            p1.i(x1.b(i2));
            i2++;
        }
    }

    public static void x(int i, List list, C3005i2 c3005i2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c3005i2.getClass();
        boolean z2 = list instanceof C3000h2;
        P1 p1 = (P1) c3005i2.a;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    p1.n(i, ((Long) list.get(i2)).longValue());
                    i2++;
                }
                return;
            }
            p1.k(i, 2);
            int iA = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                iA += P1.a(((Long) list.get(i3)).longValue());
            }
            p1.m(iA);
            while (i2 < list.size()) {
                p1.o(((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        C3000h2 c3000h2 = (C3000h2) list;
        if (!z) {
            while (i2 < c3000h2.c) {
                p1.n(i, c3000h2.b(i2));
                i2++;
            }
            return;
        }
        p1.k(i, 2);
        int iA2 = 0;
        for (int i4 = 0; i4 < c3000h2.c; i4++) {
            iA2 += P1.a(c3000h2.b(i4));
        }
        p1.m(iA2);
        while (i2 < c3000h2.c) {
            p1.o(c3000h2.b(i2));
            i2++;
        }
    }

    public static void y(int i, List list, C3005i2 c3005i2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c3005i2.getClass();
        boolean z2 = list instanceof X1;
        P1 p1 = (P1) c3005i2.a;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    p1.d(i, ((Integer) list.get(i2)).intValue());
                    i2++;
                }
                return;
            }
            p1.k(i, 2);
            int i3 = 0;
            for (int i4 = 0; i4 < list.size(); i4++) {
                ((Integer) list.get(i4)).getClass();
                i3 += 4;
            }
            p1.m(i3);
            while (i2 < list.size()) {
                p1.e(((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        X1 x1 = (X1) list;
        if (!z) {
            while (i2 < x1.c) {
                p1.d(i, x1.b(i2));
                i2++;
            }
            return;
        }
        p1.k(i, 2);
        int i5 = 0;
        for (int i6 = 0; i6 < x1.c; i6++) {
            x1.b(i6);
            i5 += 4;
        }
        p1.m(i5);
        while (i2 < x1.c) {
            p1.e(x1.b(i2));
            i2++;
        }
    }

    public static void z(int i, List list, C3005i2 c3005i2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c3005i2.getClass();
        boolean z2 = list instanceof C3000h2;
        P1 p1 = (P1) c3005i2.a;
        int i2 = 0;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    p1.f(i, ((Long) list.get(i2)).longValue());
                    i2++;
                }
                return;
            }
            p1.k(i, 2);
            int i3 = 0;
            for (int i4 = 0; i4 < list.size(); i4++) {
                ((Long) list.get(i4)).getClass();
                i3 += 8;
            }
            p1.m(i3);
            while (i2 < list.size()) {
                p1.g(((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        C3000h2 c3000h2 = (C3000h2) list;
        if (!z) {
            while (i2 < c3000h2.c) {
                p1.f(i, c3000h2.b(i2));
                i2++;
            }
            return;
        }
        p1.k(i, 2);
        int i5 = 0;
        for (int i6 = 0; i6 < c3000h2.c; i6++) {
            c3000h2.b(i6);
            i5 += 8;
        }
        p1.m(i5);
        while (i2 < c3000h2.c) {
            p1.g(c3000h2.b(i2));
            i2++;
        }
    }
}
