package androidx.glance.appwidget.protobuf;

import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

/* loaded from: classes.dex */
public abstract class P {
    public static final Class a;
    public static final Q b;
    public static final T c;

    static {
        Class<?> cls;
        Class<?> cls2;
        L l = L.c;
        Q q = null;
        try {
            cls = Class.forName("androidx.glance.appwidget.protobuf.GeneratedMessage");
        } catch (Throwable unused) {
            cls = null;
        }
        a = cls;
        try {
            L l2 = L.c;
            try {
                cls2 = Class.forName("androidx.glance.appwidget.protobuf.UnknownFieldSetSchema");
            } catch (Throwable unused2) {
                cls2 = null;
            }
            if (cls2 != null) {
                q = (Q) cls2.getConstructor(null).newInstance(null);
            }
        } catch (Throwable unused3) {
        }
        b = q;
        c = new T();
    }

    public static int a(List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iL = 0;
        for (int i = 0; i < size; i++) {
            iL += C1198j.l(((Integer) list.get(i)).intValue());
        }
        return iL;
    }

    public static int b(int i, List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return (C1198j.j(i) + 4) * size;
    }

    public static int c(int i, List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return (C1198j.j(i) + 8) * size;
    }

    public static int d(List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iL = 0;
        for (int i = 0; i < size; i++) {
            iL += C1198j.l(((Integer) list.get(i)).intValue());
        }
        return iL;
    }

    public static int e(List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iL = 0;
        for (int i = 0; i < size; i++) {
            iL += C1198j.l(((Long) list.get(i)).longValue());
        }
        return iL;
    }

    public static int f(List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iK = 0;
        for (int i = 0; i < size; i++) {
            int iIntValue = ((Integer) list.get(i)).intValue();
            iK += C1198j.k((iIntValue >> 31) ^ (iIntValue << 1));
        }
        return iK;
    }

    public static int g(List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iL = 0;
        for (int i = 0; i < size; i++) {
            long jLongValue = ((Long) list.get(i)).longValue();
            iL += C1198j.l((jLongValue >> 63) ^ (jLongValue << 1));
        }
        return iL;
    }

    public static int h(List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iK = 0;
        for (int i = 0; i < size; i++) {
            iK += C1198j.k(((Integer) list.get(i)).intValue());
        }
        return iK;
    }

    public static int i(List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iL = 0;
        for (int i = 0; i < size; i++) {
            iL += C1198j.l(((Long) list.get(i)).longValue());
        }
        return iL;
    }

    public static Object j(Object obj, int i, InterfaceC1208u interfaceC1208u, Object obj2, Q q) {
        return obj2;
    }

    public static void k(Q q, Object obj, Object obj2) {
        ((T) q).getClass();
        AbstractC1206s abstractC1206s = (AbstractC1206s) obj;
        S s = abstractC1206s.unknownFields;
        S s2 = ((AbstractC1206s) obj2).unknownFields;
        S s3 = S.f;
        if (!s3.equals(s2)) {
            if (s3.equals(s)) {
                int i = s.a + s2.a;
                int[] iArrCopyOf = Arrays.copyOf(s.b, i);
                System.arraycopy(s2.b, 0, iArrCopyOf, s.a, s2.a);
                Object[] objArrCopyOf = Arrays.copyOf(s.c, i);
                System.arraycopy(s2.c, 0, objArrCopyOf, s.a, s2.a);
                s = new S(i, iArrCopyOf, objArrCopyOf, true);
            } else {
                s.getClass();
                if (!s2.equals(s3)) {
                    if (!s.e) {
                        throw new UnsupportedOperationException();
                    }
                    int i2 = s.a + s2.a;
                    s.a(i2);
                    System.arraycopy(s2.b, 0, s.b, s.a, s2.a);
                    System.arraycopy(s2.c, 0, s.c, s.a, s2.a);
                    s.a = i2;
                }
            }
        }
        abstractC1206s.unknownFields = s;
    }

    public static boolean l(Object obj, Object obj2) {
        if (obj != obj2) {
            return obj != null && obj.equals(obj2);
        }
        return true;
    }

    public static void m(int i, List list, A a2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1198j c1198j = (C1198j) a2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1198j.p(i, ((Boolean) list.get(i2)).booleanValue());
                i2++;
            }
            return;
        }
        c1198j.z(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Boolean) list.get(i4)).getClass();
            Logger logger = C1198j.g;
            i3++;
        }
        c1198j.B(i3);
        while (i2 < list.size()) {
            byte b2 = ((Boolean) list.get(i2)).booleanValue() ? (byte) 1 : (byte) 0;
            if (c1198j.e == c1198j.d) {
                c1198j.m();
            }
            int i5 = c1198j.e;
            c1198j.e = i5 + 1;
            c1198j.c[i5] = b2;
            i2++;
        }
    }

    public static void n(int i, List list, A a2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1198j c1198j = (C1198j) a2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                double dDoubleValue = ((Double) list.get(i2)).doubleValue();
                c1198j.getClass();
                c1198j.t(i, Double.doubleToRawLongBits(dDoubleValue));
                i2++;
            }
            return;
        }
        c1198j.z(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Double) list.get(i4)).getClass();
            Logger logger = C1198j.g;
            i3 += 8;
        }
        c1198j.B(i3);
        while (i2 < list.size()) {
            c1198j.u(Double.doubleToRawLongBits(((Double) list.get(i2)).doubleValue()));
            i2++;
        }
    }

    public static void o(int i, List list, A a2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1198j c1198j = (C1198j) a2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1198j.v(i, ((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        c1198j.z(i, 2);
        int iL = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iL += C1198j.l(((Integer) list.get(i3)).intValue());
        }
        c1198j.B(iL);
        while (i2 < list.size()) {
            c1198j.w(((Integer) list.get(i2)).intValue());
            i2++;
        }
    }

    public static void p(int i, List list, A a2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1198j c1198j = (C1198j) a2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1198j.r(i, ((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        c1198j.z(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Integer) list.get(i4)).getClass();
            Logger logger = C1198j.g;
            i3 += 4;
        }
        c1198j.B(i3);
        while (i2 < list.size()) {
            c1198j.s(((Integer) list.get(i2)).intValue());
            i2++;
        }
    }

    public static void q(int i, List list, A a2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1198j c1198j = (C1198j) a2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1198j.t(i, ((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        c1198j.z(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Long) list.get(i4)).getClass();
            Logger logger = C1198j.g;
            i3 += 8;
        }
        c1198j.B(i3);
        while (i2 < list.size()) {
            c1198j.u(((Long) list.get(i2)).longValue());
            i2++;
        }
    }

    public static void r(int i, List list, A a2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1198j c1198j = (C1198j) a2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                float fFloatValue = ((Float) list.get(i2)).floatValue();
                c1198j.getClass();
                c1198j.r(i, Float.floatToRawIntBits(fFloatValue));
                i2++;
            }
            return;
        }
        c1198j.z(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Float) list.get(i4)).getClass();
            Logger logger = C1198j.g;
            i3 += 4;
        }
        c1198j.B(i3);
        while (i2 < list.size()) {
            c1198j.s(Float.floatToRawIntBits(((Float) list.get(i2)).floatValue()));
            i2++;
        }
    }

    public static void s(int i, List list, A a2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1198j c1198j = (C1198j) a2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1198j.v(i, ((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        c1198j.z(i, 2);
        int iL = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iL += C1198j.l(((Integer) list.get(i3)).intValue());
        }
        c1198j.B(iL);
        while (i2 < list.size()) {
            c1198j.w(((Integer) list.get(i2)).intValue());
            i2++;
        }
    }

    public static void t(int i, List list, A a2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1198j c1198j = (C1198j) a2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1198j.C(i, ((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        c1198j.z(i, 2);
        int iL = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iL += C1198j.l(((Long) list.get(i3)).longValue());
        }
        c1198j.B(iL);
        while (i2 < list.size()) {
            c1198j.D(((Long) list.get(i2)).longValue());
            i2++;
        }
    }

    public static void u(int i, List list, A a2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1198j c1198j = (C1198j) a2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1198j.r(i, ((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        c1198j.z(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Integer) list.get(i4)).getClass();
            Logger logger = C1198j.g;
            i3 += 4;
        }
        c1198j.B(i3);
        while (i2 < list.size()) {
            c1198j.s(((Integer) list.get(i2)).intValue());
            i2++;
        }
    }

    public static void v(int i, List list, A a2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1198j c1198j = (C1198j) a2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1198j.t(i, ((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        c1198j.z(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Long) list.get(i4)).getClass();
            Logger logger = C1198j.g;
            i3 += 8;
        }
        c1198j.B(i3);
        while (i2 < list.size()) {
            c1198j.u(((Long) list.get(i2)).longValue());
            i2++;
        }
    }

    public static void w(int i, List list, A a2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1198j c1198j = (C1198j) a2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                int iIntValue = ((Integer) list.get(i2)).intValue();
                c1198j.A(i, (iIntValue >> 31) ^ (iIntValue << 1));
                i2++;
            }
            return;
        }
        c1198j.z(i, 2);
        int iK = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            int iIntValue2 = ((Integer) list.get(i3)).intValue();
            iK += C1198j.k((iIntValue2 >> 31) ^ (iIntValue2 << 1));
        }
        c1198j.B(iK);
        while (i2 < list.size()) {
            int iIntValue3 = ((Integer) list.get(i2)).intValue();
            c1198j.B((iIntValue3 >> 31) ^ (iIntValue3 << 1));
            i2++;
        }
    }

    public static void x(int i, List list, A a2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1198j c1198j = (C1198j) a2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                long jLongValue = ((Long) list.get(i2)).longValue();
                c1198j.C(i, (jLongValue >> 63) ^ (jLongValue << 1));
                i2++;
            }
            return;
        }
        c1198j.z(i, 2);
        int iL = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            long jLongValue2 = ((Long) list.get(i3)).longValue();
            iL += C1198j.l((jLongValue2 >> 63) ^ (jLongValue2 << 1));
        }
        c1198j.B(iL);
        while (i2 < list.size()) {
            long jLongValue3 = ((Long) list.get(i2)).longValue();
            c1198j.D((jLongValue3 >> 63) ^ (jLongValue3 << 1));
            i2++;
        }
    }

    public static void y(int i, List list, A a2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1198j c1198j = (C1198j) a2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1198j.A(i, ((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        c1198j.z(i, 2);
        int iK = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iK += C1198j.k(((Integer) list.get(i3)).intValue());
        }
        c1198j.B(iK);
        while (i2 < list.size()) {
            c1198j.B(((Integer) list.get(i2)).intValue());
            i2++;
        }
    }

    public static void z(int i, List list, A a2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1198j c1198j = (C1198j) a2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1198j.C(i, ((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        c1198j.z(i, 2);
        int iL = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iL += C1198j.l(((Long) list.get(i3)).longValue());
        }
        c1198j.B(iL);
        while (i2 < list.size()) {
            c1198j.D(((Long) list.get(i2)).longValue());
            i2++;
        }
    }
}
