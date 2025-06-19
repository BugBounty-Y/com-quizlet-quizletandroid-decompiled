package androidx.datastore.preferences.protobuf;

import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

/* loaded from: classes.dex */
public abstract class V {
    public static final Class a;
    public static final Z b;
    public static final b0 c;

    static {
        Class<?> cls;
        Class<?> cls2;
        Q q = Q.c;
        Z z = null;
        try {
            cls = Class.forName("androidx.datastore.preferences.protobuf.GeneratedMessage");
        } catch (Throwable unused) {
            cls = null;
        }
        a = cls;
        try {
            Q q2 = Q.c;
            try {
                cls2 = Class.forName("androidx.datastore.preferences.protobuf.UnknownFieldSetSchema");
            } catch (Throwable unused2) {
                cls2 = null;
            }
            if (cls2 != null) {
                z = (Z) cls2.getConstructor(null).newInstance(null);
            }
        } catch (Throwable unused3) {
        }
        b = z;
        c = new b0();
    }

    public static int a(List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iL = 0;
        for (int i = 0; i < size; i++) {
            iL += C1104k.l(((Integer) list.get(i)).intValue());
        }
        return iL;
    }

    public static int b(int i, List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return (C1104k.j(i) + 4) * size;
    }

    public static int c(int i, List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return (C1104k.j(i) + 8) * size;
    }

    public static int d(List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iL = 0;
        for (int i = 0; i < size; i++) {
            iL += C1104k.l(((Integer) list.get(i)).intValue());
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
            iL += C1104k.l(((Long) list.get(i)).longValue());
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
            iK += C1104k.k((iIntValue >> 31) ^ (iIntValue << 1));
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
            iL += C1104k.l((jLongValue >> 63) ^ (jLongValue << 1));
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
            iK += C1104k.k(((Integer) list.get(i)).intValue());
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
            iL += C1104k.l(((Long) list.get(i)).longValue());
        }
        return iL;
    }

    public static Object j(Object obj, int i, InterfaceC1114v interfaceC1114v, Object obj2, Z z) {
        return obj2;
    }

    public static void k(Z z, Object obj, Object obj2) {
        ((b0) z).getClass();
        AbstractC1113u abstractC1113u = (AbstractC1113u) obj;
        a0 a0Var = abstractC1113u.unknownFields;
        a0 a0Var2 = ((AbstractC1113u) obj2).unknownFields;
        a0 a0Var3 = a0.f;
        if (!a0Var3.equals(a0Var2)) {
            if (a0Var3.equals(a0Var)) {
                int i = a0Var.a + a0Var2.a;
                int[] iArrCopyOf = Arrays.copyOf(a0Var.b, i);
                System.arraycopy(a0Var2.b, 0, iArrCopyOf, a0Var.a, a0Var2.a);
                Object[] objArrCopyOf = Arrays.copyOf(a0Var.c, i);
                System.arraycopy(a0Var2.c, 0, objArrCopyOf, a0Var.a, a0Var2.a);
                a0Var = new a0(i, iArrCopyOf, objArrCopyOf, true);
            } else {
                a0Var.getClass();
                if (!a0Var2.equals(a0Var3)) {
                    if (!a0Var.e) {
                        throw new UnsupportedOperationException();
                    }
                    int i2 = a0Var.a + a0Var2.a;
                    a0Var.a(i2);
                    System.arraycopy(a0Var2.b, 0, a0Var.b, a0Var.a, a0Var2.a);
                    System.arraycopy(a0Var2.c, 0, a0Var.c, a0Var.a, a0Var2.a);
                    a0Var.a = i2;
                }
            }
        }
        abstractC1113u.unknownFields = a0Var;
    }

    public static boolean l(Object obj, Object obj2) {
        if (obj != obj2) {
            return obj != null && obj.equals(obj2);
        }
        return true;
    }

    public static void m(int i, List list, C c2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1104k c1104k = (C1104k) c2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1104k.q(i, ((Boolean) list.get(i2)).booleanValue());
                i2++;
            }
            return;
        }
        c1104k.C(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Boolean) list.get(i4)).getClass();
            Logger logger = C1104k.g;
            i3++;
        }
        c1104k.E(i3);
        while (i2 < list.size()) {
            c1104k.o(((Boolean) list.get(i2)).booleanValue() ? (byte) 1 : (byte) 0);
            i2++;
        }
    }

    public static void n(int i, List list, C c2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1104k c1104k = (C1104k) c2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                double dDoubleValue = ((Double) list.get(i2)).doubleValue();
                c1104k.getClass();
                c1104k.v(i, Double.doubleToRawLongBits(dDoubleValue));
                i2++;
            }
            return;
        }
        c1104k.C(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Double) list.get(i4)).getClass();
            Logger logger = C1104k.g;
            i3 += 8;
        }
        c1104k.E(i3);
        while (i2 < list.size()) {
            c1104k.w(Double.doubleToRawLongBits(((Double) list.get(i2)).doubleValue()));
            i2++;
        }
    }

    public static void o(int i, List list, C c2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1104k c1104k = (C1104k) c2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1104k.x(i, ((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        c1104k.C(i, 2);
        int iL = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iL += C1104k.l(((Integer) list.get(i3)).intValue());
        }
        c1104k.E(iL);
        while (i2 < list.size()) {
            c1104k.y(((Integer) list.get(i2)).intValue());
            i2++;
        }
    }

    public static void p(int i, List list, C c2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1104k c1104k = (C1104k) c2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1104k.t(i, ((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        c1104k.C(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Integer) list.get(i4)).getClass();
            Logger logger = C1104k.g;
            i3 += 4;
        }
        c1104k.E(i3);
        while (i2 < list.size()) {
            c1104k.u(((Integer) list.get(i2)).intValue());
            i2++;
        }
    }

    public static void q(int i, List list, C c2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1104k c1104k = (C1104k) c2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1104k.v(i, ((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        c1104k.C(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Long) list.get(i4)).getClass();
            Logger logger = C1104k.g;
            i3 += 8;
        }
        c1104k.E(i3);
        while (i2 < list.size()) {
            c1104k.w(((Long) list.get(i2)).longValue());
            i2++;
        }
    }

    public static void r(int i, List list, C c2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1104k c1104k = (C1104k) c2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                float fFloatValue = ((Float) list.get(i2)).floatValue();
                c1104k.getClass();
                c1104k.t(i, Float.floatToRawIntBits(fFloatValue));
                i2++;
            }
            return;
        }
        c1104k.C(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Float) list.get(i4)).getClass();
            Logger logger = C1104k.g;
            i3 += 4;
        }
        c1104k.E(i3);
        while (i2 < list.size()) {
            c1104k.u(Float.floatToRawIntBits(((Float) list.get(i2)).floatValue()));
            i2++;
        }
    }

    public static void s(int i, List list, C c2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1104k c1104k = (C1104k) c2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1104k.x(i, ((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        c1104k.C(i, 2);
        int iL = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iL += C1104k.l(((Integer) list.get(i3)).intValue());
        }
        c1104k.E(iL);
        while (i2 < list.size()) {
            c1104k.y(((Integer) list.get(i2)).intValue());
            i2++;
        }
    }

    public static void t(int i, List list, C c2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1104k c1104k = (C1104k) c2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1104k.F(i, ((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        c1104k.C(i, 2);
        int iL = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iL += C1104k.l(((Long) list.get(i3)).longValue());
        }
        c1104k.E(iL);
        while (i2 < list.size()) {
            c1104k.G(((Long) list.get(i2)).longValue());
            i2++;
        }
    }

    public static void u(int i, List list, C c2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1104k c1104k = (C1104k) c2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1104k.t(i, ((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        c1104k.C(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Integer) list.get(i4)).getClass();
            Logger logger = C1104k.g;
            i3 += 4;
        }
        c1104k.E(i3);
        while (i2 < list.size()) {
            c1104k.u(((Integer) list.get(i2)).intValue());
            i2++;
        }
    }

    public static void v(int i, List list, C c2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1104k c1104k = (C1104k) c2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1104k.v(i, ((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        c1104k.C(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Long) list.get(i4)).getClass();
            Logger logger = C1104k.g;
            i3 += 8;
        }
        c1104k.E(i3);
        while (i2 < list.size()) {
            c1104k.w(((Long) list.get(i2)).longValue());
            i2++;
        }
    }

    public static void w(int i, List list, C c2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1104k c1104k = (C1104k) c2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                int iIntValue = ((Integer) list.get(i2)).intValue();
                c1104k.D(i, (iIntValue >> 31) ^ (iIntValue << 1));
                i2++;
            }
            return;
        }
        c1104k.C(i, 2);
        int iK = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            int iIntValue2 = ((Integer) list.get(i3)).intValue();
            iK += C1104k.k((iIntValue2 >> 31) ^ (iIntValue2 << 1));
        }
        c1104k.E(iK);
        while (i2 < list.size()) {
            int iIntValue3 = ((Integer) list.get(i2)).intValue();
            c1104k.E((iIntValue3 >> 31) ^ (iIntValue3 << 1));
            i2++;
        }
    }

    public static void x(int i, List list, C c2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1104k c1104k = (C1104k) c2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                long jLongValue = ((Long) list.get(i2)).longValue();
                c1104k.F(i, (jLongValue >> 63) ^ (jLongValue << 1));
                i2++;
            }
            return;
        }
        c1104k.C(i, 2);
        int iL = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            long jLongValue2 = ((Long) list.get(i3)).longValue();
            iL += C1104k.l((jLongValue2 >> 63) ^ (jLongValue2 << 1));
        }
        c1104k.E(iL);
        while (i2 < list.size()) {
            long jLongValue3 = ((Long) list.get(i2)).longValue();
            c1104k.G((jLongValue3 >> 63) ^ (jLongValue3 << 1));
            i2++;
        }
    }

    public static void y(int i, List list, C c2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1104k c1104k = (C1104k) c2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1104k.D(i, ((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        c1104k.C(i, 2);
        int iK = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iK += C1104k.k(((Integer) list.get(i3)).intValue());
        }
        c1104k.E(iK);
        while (i2 < list.size()) {
            c1104k.E(((Integer) list.get(i2)).intValue());
            i2++;
        }
    }

    public static void z(int i, List list, C c2, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        C1104k c1104k = (C1104k) c2.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                c1104k.F(i, ((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        c1104k.C(i, 2);
        int iL = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iL += C1104k.l(((Long) list.get(i3)).longValue());
        }
        c1104k.E(iL);
        while (i2 < list.size()) {
            c1104k.G(((Long) list.get(i2)).longValue());
            i2++;
        }
    }
}
