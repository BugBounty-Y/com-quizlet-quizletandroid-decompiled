package com.google.android.gms.internal.play_billing;

import java.util.Arrays;
import java.util.List;

/* renamed from: com.google.android.gms.internal.play_billing.z1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3855z1 {
    public static final C3781a1 a;

    static {
        C3843v1 c3843v1 = C3843v1.c;
        a = new C3781a1(6);
    }

    public static void a(int i, List list, C3817m1 c3817m1, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c3817m1.getClass();
        boolean z2 = list instanceof C3790d1;
        int i2 = 0;
        V0 v0 = (V0) c3817m1.a;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    int iIntValue = ((Integer) list.get(i2)).intValue();
                    v0.Z(i, (iIntValue >> 31) ^ (iIntValue + iIntValue));
                    i2++;
                }
                return;
            }
            v0.Y(i, 2);
            int iE0 = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                int iIntValue2 = ((Integer) list.get(i3)).intValue();
                iE0 += V0.e0((iIntValue2 >> 31) ^ (iIntValue2 + iIntValue2));
            }
            v0.a0(iE0);
            while (i2 < list.size()) {
                int iIntValue3 = ((Integer) list.get(i2)).intValue();
                v0.a0((iIntValue3 >> 31) ^ (iIntValue3 + iIntValue3));
                i2++;
            }
            return;
        }
        C3790d1 c3790d1 = (C3790d1) list;
        if (!z) {
            while (i2 < c3790d1.c) {
                int iB = c3790d1.b(i2);
                v0.Z(i, (iB >> 31) ^ (iB + iB));
                i2++;
            }
            return;
        }
        v0.Y(i, 2);
        int iE02 = 0;
        for (int i4 = 0; i4 < c3790d1.c; i4++) {
            int iB2 = c3790d1.b(i4);
            iE02 += V0.e0((iB2 >> 31) ^ (iB2 + iB2));
        }
        v0.a0(iE02);
        while (i2 < c3790d1.c) {
            int iB3 = c3790d1.b(i2);
            v0.a0((iB3 >> 31) ^ (iB3 + iB3));
            i2++;
        }
    }

    public static void b(int i, List list, C3817m1 c3817m1, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        V0 v0 = (V0) c3817m1.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                long jLongValue = ((Long) list.get(i2)).longValue();
                v0.b0(i, (jLongValue >> 63) ^ (jLongValue + jLongValue));
                i2++;
            }
            return;
        }
        v0.Y(i, 2);
        int iO = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            long jLongValue2 = ((Long) list.get(i3)).longValue();
            iO += V0.O((jLongValue2 >> 63) ^ (jLongValue2 + jLongValue2));
        }
        v0.a0(iO);
        while (i2 < list.size()) {
            long jLongValue3 = ((Long) list.get(i2)).longValue();
            v0.c0((jLongValue3 >> 63) ^ (jLongValue3 + jLongValue3));
            i2++;
        }
    }

    public static void c(int i, List list, C3817m1 c3817m1, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c3817m1.getClass();
        boolean z2 = list instanceof C3790d1;
        int i2 = 0;
        V0 v0 = (V0) c3817m1.a;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    v0.Z(i, ((Integer) list.get(i2)).intValue());
                    i2++;
                }
                return;
            }
            v0.Y(i, 2);
            int iE0 = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                iE0 += V0.e0(((Integer) list.get(i3)).intValue());
            }
            v0.a0(iE0);
            while (i2 < list.size()) {
                v0.a0(((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        C3790d1 c3790d1 = (C3790d1) list;
        if (!z) {
            while (i2 < c3790d1.c) {
                v0.Z(i, c3790d1.b(i2));
                i2++;
            }
            return;
        }
        v0.Y(i, 2);
        int iE02 = 0;
        for (int i4 = 0; i4 < c3790d1.c; i4++) {
            iE02 += V0.e0(c3790d1.b(i4));
        }
        v0.a0(iE02);
        while (i2 < c3790d1.c) {
            v0.a0(c3790d1.b(i2));
            i2++;
        }
    }

    public static void d(int i, List list, C3817m1 c3817m1, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        V0 v0 = (V0) c3817m1.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                v0.b0(i, ((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        v0.Y(i, 2);
        int iO = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iO += V0.O(((Long) list.get(i3)).longValue());
        }
        v0.a0(iO);
        while (i2 < list.size()) {
            v0.c0(((Long) list.get(i2)).longValue());
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
        if (!(list instanceof C3790d1)) {
            int iO = 0;
            while (i < size) {
                iO += V0.O(((Integer) list.get(i)).intValue());
                i++;
            }
            return iO;
        }
        C3790d1 c3790d1 = (C3790d1) list;
        int iO2 = 0;
        while (i < size) {
            iO2 += V0.O(c3790d1.b(i));
            i++;
        }
        return iO2;
    }

    public static int g(int i, List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return (V0.e0(i << 3) + 4) * size;
    }

    public static int h(int i, List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return (V0.e0(i << 3) + 8) * size;
    }

    public static int i(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof C3790d1)) {
            int iO = 0;
            while (i < size) {
                iO += V0.O(((Integer) list.get(i)).intValue());
                i++;
            }
            return iO;
        }
        C3790d1 c3790d1 = (C3790d1) list;
        int iO2 = 0;
        while (i < size) {
            iO2 += V0.O(c3790d1.b(i));
            i++;
        }
        return iO2;
    }

    public static int j(List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iO = 0;
        for (int i = 0; i < size; i++) {
            iO += V0.O(((Long) list.get(i)).longValue());
        }
        return iO;
    }

    public static int k(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof C3790d1)) {
            int iE0 = 0;
            while (i < size) {
                int iIntValue = ((Integer) list.get(i)).intValue();
                iE0 += V0.e0((iIntValue >> 31) ^ (iIntValue + iIntValue));
                i++;
            }
            return iE0;
        }
        C3790d1 c3790d1 = (C3790d1) list;
        int iE02 = 0;
        while (i < size) {
            int iB = c3790d1.b(i);
            iE02 += V0.e0((iB >> 31) ^ (iB + iB));
            i++;
        }
        return iE02;
    }

    public static int l(List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iO = 0;
        for (int i = 0; i < size; i++) {
            long jLongValue = ((Long) list.get(i)).longValue();
            iO += V0.O((jLongValue >> 63) ^ (jLongValue + jLongValue));
        }
        return iO;
    }

    public static int m(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof C3790d1)) {
            int iE0 = 0;
            while (i < size) {
                iE0 += V0.e0(((Integer) list.get(i)).intValue());
                i++;
            }
            return iE0;
        }
        C3790d1 c3790d1 = (C3790d1) list;
        int iE02 = 0;
        while (i < size) {
            iE02 += V0.e0(c3790d1.b(i));
            i++;
        }
        return iE02;
    }

    public static int n(List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iO = 0;
        for (int i = 0; i < size; i++) {
            iO += V0.O(((Long) list.get(i)).longValue());
        }
        return iO;
    }

    public static Object o(Object obj, int i, Object obj2, int i2) {
        Object obj3 = obj2;
        if (obj2 == null) {
            AbstractC3787c1 abstractC3787c1 = (AbstractC3787c1) obj;
            B1 b1 = abstractC3787c1.zzc;
            obj3 = b1;
            if (b1 == B1.f) {
                B1 b1B = B1.b();
                abstractC3787c1.zzc = b1B;
                obj3 = b1B;
            }
        }
        ((B1) obj3).c(i << 3, Long.valueOf(i2));
        return obj3;
    }

    public static void p(Object obj, Object obj2) {
        AbstractC3787c1 abstractC3787c1 = (AbstractC3787c1) obj;
        B1 b1 = abstractC3787c1.zzc;
        B1 b12 = ((AbstractC3787c1) obj2).zzc;
        B1 b13 = B1.f;
        if (!b13.equals(b12)) {
            if (b13.equals(b1)) {
                int i = b1.a + b12.a;
                int[] iArrCopyOf = Arrays.copyOf(b1.b, i);
                System.arraycopy(b12.b, 0, iArrCopyOf, b1.a, b12.a);
                Object[] objArrCopyOf = Arrays.copyOf(b1.c, i);
                System.arraycopy(b12.c, 0, objArrCopyOf, b1.a, b12.a);
                b1 = new B1(i, iArrCopyOf, objArrCopyOf, true);
            } else {
                b1.getClass();
                if (!b12.equals(b13)) {
                    if (!b1.e) {
                        throw new UnsupportedOperationException();
                    }
                    int i2 = b1.a + b12.a;
                    b1.e(i2);
                    System.arraycopy(b12.b, 0, b1.b, b1.a, b12.a);
                    System.arraycopy(b12.c, 0, b1.c, b1.a, b12.a);
                    b1.a = i2;
                }
            }
        }
        abstractC3787c1.zzc = b1;
    }

    public static void q(int i, List list, C3817m1 c3817m1, boolean z) {
        IndexOutOfBoundsException indexOutOfBoundsException;
        IndexOutOfBoundsException indexOutOfBoundsException2;
        if (list == null || list.isEmpty()) {
            return;
        }
        V0 v0 = (V0) c3817m1.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                byte bBooleanValue = ((Boolean) list.get(i2)).booleanValue();
                v0.a0(i << 3);
                int i3 = v0.e;
                try {
                    int i4 = i3 + 1;
                    try {
                        v0.c[i3] = bBooleanValue;
                        v0.e = i4;
                        i2++;
                    } catch (IndexOutOfBoundsException e) {
                        indexOutOfBoundsException = e;
                        i3 = i4;
                        throw new zzgp(i3, v0.d, 1, indexOutOfBoundsException);
                    }
                } catch (IndexOutOfBoundsException e2) {
                    indexOutOfBoundsException = e2;
                }
            }
            return;
        }
        v0.Y(i, 2);
        int i5 = 0;
        for (int i6 = 0; i6 < list.size(); i6++) {
            ((Boolean) list.get(i6)).getClass();
            i5++;
        }
        v0.a0(i5);
        while (i2 < list.size()) {
            byte bBooleanValue2 = ((Boolean) list.get(i2)).booleanValue();
            int i7 = v0.e;
            try {
                int i8 = i7 + 1;
                try {
                    v0.c[i7] = bBooleanValue2;
                    v0.e = i8;
                    i2++;
                } catch (IndexOutOfBoundsException e3) {
                    indexOutOfBoundsException2 = e3;
                    i7 = i8;
                    throw new zzgp(i7, v0.d, 1, indexOutOfBoundsException2);
                }
            } catch (IndexOutOfBoundsException e4) {
                indexOutOfBoundsException2 = e4;
            }
        }
    }

    public static void r(int i, List list, C3817m1 c3817m1, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        V0 v0 = (V0) c3817m1.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                v0.T(i, Double.doubleToRawLongBits(((Double) list.get(i2)).doubleValue()));
                i2++;
            }
            return;
        }
        v0.Y(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Double) list.get(i4)).getClass();
            i3 += 8;
        }
        v0.a0(i3);
        while (i2 < list.size()) {
            v0.U(Double.doubleToRawLongBits(((Double) list.get(i2)).doubleValue()));
            i2++;
        }
    }

    public static void s(int i, List list, C3817m1 c3817m1, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c3817m1.getClass();
        boolean z2 = list instanceof C3790d1;
        int i2 = 0;
        V0 v0 = (V0) c3817m1.a;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    v0.V(i, ((Integer) list.get(i2)).intValue());
                    i2++;
                }
                return;
            }
            v0.Y(i, 2);
            int iO = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                iO += V0.O(((Integer) list.get(i3)).intValue());
            }
            v0.a0(iO);
            while (i2 < list.size()) {
                v0.W(((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        C3790d1 c3790d1 = (C3790d1) list;
        if (!z) {
            while (i2 < c3790d1.c) {
                v0.V(i, c3790d1.b(i2));
                i2++;
            }
            return;
        }
        v0.Y(i, 2);
        int iO2 = 0;
        for (int i4 = 0; i4 < c3790d1.c; i4++) {
            iO2 += V0.O(c3790d1.b(i4));
        }
        v0.a0(iO2);
        while (i2 < c3790d1.c) {
            v0.W(c3790d1.b(i2));
            i2++;
        }
    }

    public static void t(int i, List list, C3817m1 c3817m1, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c3817m1.getClass();
        boolean z2 = list instanceof C3790d1;
        int i2 = 0;
        V0 v0 = (V0) c3817m1.a;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    v0.R(i, ((Integer) list.get(i2)).intValue());
                    i2++;
                }
                return;
            }
            v0.Y(i, 2);
            int i3 = 0;
            for (int i4 = 0; i4 < list.size(); i4++) {
                ((Integer) list.get(i4)).getClass();
                i3 += 4;
            }
            v0.a0(i3);
            while (i2 < list.size()) {
                v0.S(((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        C3790d1 c3790d1 = (C3790d1) list;
        if (!z) {
            while (i2 < c3790d1.c) {
                v0.R(i, c3790d1.b(i2));
                i2++;
            }
            return;
        }
        v0.Y(i, 2);
        int i5 = 0;
        for (int i6 = 0; i6 < c3790d1.c; i6++) {
            c3790d1.b(i6);
            i5 += 4;
        }
        v0.a0(i5);
        while (i2 < c3790d1.c) {
            v0.S(c3790d1.b(i2));
            i2++;
        }
    }

    public static void u(int i, List list, C3817m1 c3817m1, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        V0 v0 = (V0) c3817m1.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                v0.T(i, ((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        v0.Y(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Long) list.get(i4)).getClass();
            i3 += 8;
        }
        v0.a0(i3);
        while (i2 < list.size()) {
            v0.U(((Long) list.get(i2)).longValue());
            i2++;
        }
    }

    public static void v(int i, List list, C3817m1 c3817m1, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        V0 v0 = (V0) c3817m1.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                v0.R(i, Float.floatToRawIntBits(((Float) list.get(i2)).floatValue()));
                i2++;
            }
            return;
        }
        v0.Y(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Float) list.get(i4)).getClass();
            i3 += 4;
        }
        v0.a0(i3);
        while (i2 < list.size()) {
            v0.S(Float.floatToRawIntBits(((Float) list.get(i2)).floatValue()));
            i2++;
        }
    }

    public static void w(int i, List list, C3817m1 c3817m1, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c3817m1.getClass();
        boolean z2 = list instanceof C3790d1;
        int i2 = 0;
        V0 v0 = (V0) c3817m1.a;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    v0.V(i, ((Integer) list.get(i2)).intValue());
                    i2++;
                }
                return;
            }
            v0.Y(i, 2);
            int iO = 0;
            for (int i3 = 0; i3 < list.size(); i3++) {
                iO += V0.O(((Integer) list.get(i3)).intValue());
            }
            v0.a0(iO);
            while (i2 < list.size()) {
                v0.W(((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        C3790d1 c3790d1 = (C3790d1) list;
        if (!z) {
            while (i2 < c3790d1.c) {
                v0.V(i, c3790d1.b(i2));
                i2++;
            }
            return;
        }
        v0.Y(i, 2);
        int iO2 = 0;
        for (int i4 = 0; i4 < c3790d1.c; i4++) {
            iO2 += V0.O(c3790d1.b(i4));
        }
        v0.a0(iO2);
        while (i2 < c3790d1.c) {
            v0.W(c3790d1.b(i2));
            i2++;
        }
    }

    public static void x(int i, List list, C3817m1 c3817m1, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        V0 v0 = (V0) c3817m1.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                v0.b0(i, ((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        v0.Y(i, 2);
        int iO = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iO += V0.O(((Long) list.get(i3)).longValue());
        }
        v0.a0(iO);
        while (i2 < list.size()) {
            v0.c0(((Long) list.get(i2)).longValue());
            i2++;
        }
    }

    public static void y(int i, List list, C3817m1 c3817m1, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        c3817m1.getClass();
        boolean z2 = list instanceof C3790d1;
        int i2 = 0;
        V0 v0 = (V0) c3817m1.a;
        if (!z2) {
            if (!z) {
                while (i2 < list.size()) {
                    v0.R(i, ((Integer) list.get(i2)).intValue());
                    i2++;
                }
                return;
            }
            v0.Y(i, 2);
            int i3 = 0;
            for (int i4 = 0; i4 < list.size(); i4++) {
                ((Integer) list.get(i4)).getClass();
                i3 += 4;
            }
            v0.a0(i3);
            while (i2 < list.size()) {
                v0.S(((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        C3790d1 c3790d1 = (C3790d1) list;
        if (!z) {
            while (i2 < c3790d1.c) {
                v0.R(i, c3790d1.b(i2));
                i2++;
            }
            return;
        }
        v0.Y(i, 2);
        int i5 = 0;
        for (int i6 = 0; i6 < c3790d1.c; i6++) {
            c3790d1.b(i6);
            i5 += 4;
        }
        v0.a0(i5);
        while (i2 < c3790d1.c) {
            v0.S(c3790d1.b(i2));
            i2++;
        }
    }

    public static void z(int i, List list, C3817m1 c3817m1, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        V0 v0 = (V0) c3817m1.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                v0.T(i, ((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        v0.Y(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Long) list.get(i4)).getClass();
            i3 += 8;
        }
        v0.a0(i3);
        while (i2 < list.size()) {
            v0.U(((Long) list.get(i2)).longValue());
            i2++;
        }
    }
}
