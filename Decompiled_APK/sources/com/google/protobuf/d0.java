package com.google.protobuf;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.RandomAccess;
import java.util.logging.Logger;

/* loaded from: classes2.dex */
public abstract class d0 {
    public static final Class a;
    public static final j0 b;
    public static final l0 c;

    static {
        Class<?> cls;
        Class<?> cls2;
        j0 j0Var = null;
        try {
            cls = Class.forName("com.google.protobuf.GeneratedMessage");
        } catch (Throwable unused) {
            cls = null;
        }
        a = cls;
        try {
            cls2 = Class.forName("com.google.protobuf.UnknownFieldSetSchema");
        } catch (Throwable unused2) {
            cls2 = null;
        }
        if (cls2 != null) {
            try {
                j0Var = (j0) cls2.getConstructor(null).newInstance(null);
            } catch (Throwable unused3) {
            }
        }
        b = j0Var;
        c = new l0();
    }

    public static int a(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof C4028w)) {
            int iL = 0;
            while (i < size) {
                iL += AbstractC4018l.l(((Integer) list.get(i)).intValue());
                i++;
            }
            return iL;
        }
        C4028w c4028w = (C4028w) list;
        int iL2 = 0;
        while (i < size) {
            iL2 += AbstractC4018l.l(c4028w.e(i));
            i++;
        }
        return iL2;
    }

    public static int b(int i, List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return (AbstractC4018l.j(i) + 4) * size;
    }

    public static int c(int i, List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return (AbstractC4018l.j(i) + 8) * size;
    }

    public static int d(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof C4028w)) {
            int iL = 0;
            while (i < size) {
                iL += AbstractC4018l.l(((Integer) list.get(i)).intValue());
                i++;
            }
            return iL;
        }
        C4028w c4028w = (C4028w) list;
        int iL2 = 0;
        while (i < size) {
            iL2 += AbstractC4018l.l(c4028w.e(i));
            i++;
        }
        return iL2;
    }

    public static int e(List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iL = 0;
        for (int i = 0; i < size; i++) {
            iL += AbstractC4018l.l(((Long) list.get(i)).longValue());
        }
        return iL;
    }

    public static int f(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof C4028w)) {
            int iK = 0;
            while (i < size) {
                int iIntValue = ((Integer) list.get(i)).intValue();
                iK += AbstractC4018l.k((iIntValue >> 31) ^ (iIntValue << 1));
                i++;
            }
            return iK;
        }
        C4028w c4028w = (C4028w) list;
        int iK2 = 0;
        while (i < size) {
            int iE = c4028w.e(i);
            iK2 += AbstractC4018l.k((iE >> 31) ^ (iE << 1));
            i++;
        }
        return iK2;
    }

    public static int g(List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iL = 0;
        for (int i = 0; i < size; i++) {
            long jLongValue = ((Long) list.get(i)).longValue();
            iL += AbstractC4018l.l((jLongValue >> 63) ^ (jLongValue << 1));
        }
        return iL;
    }

    public static int h(List list) {
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (!(list instanceof C4028w)) {
            int iK = 0;
            while (i < size) {
                iK += AbstractC4018l.k(((Integer) list.get(i)).intValue());
                i++;
            }
            return iK;
        }
        C4028w c4028w = (C4028w) list;
        int iK2 = 0;
        while (i < size) {
            iK2 += AbstractC4018l.k(c4028w.e(i));
            i++;
        }
        return iK2;
    }

    public static int i(List list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iL = 0;
        for (int i = 0; i < size; i++) {
            iL += AbstractC4018l.l(((Long) list.get(i)).longValue());
        }
        return iL;
    }

    public static Object j(Object obj, int i, List list, InterfaceC4030y interfaceC4030y, Object obj2, j0 j0Var) {
        if (interfaceC4030y == null) {
            return obj2;
        }
        if (!(list instanceof RandomAccess)) {
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                int iIntValue = ((Integer) it2.next()).intValue();
                if (!interfaceC4030y.a(iIntValue)) {
                    if (obj2 == null) {
                        obj2 = j0Var.a(obj);
                    }
                    ((l0) j0Var).getClass();
                    ((k0) obj2).c(i << 3, Long.valueOf(iIntValue));
                    it2.remove();
                }
            }
            return obj2;
        }
        int size = list.size();
        int i2 = 0;
        for (int i3 = 0; i3 < size; i3++) {
            Integer num = (Integer) list.get(i3);
            int iIntValue2 = num.intValue();
            if (interfaceC4030y.a(iIntValue2)) {
                if (i3 != i2) {
                    list.set(i2, num);
                }
                i2++;
            } else {
                if (obj2 == null) {
                    obj2 = j0Var.a(obj);
                }
                ((l0) j0Var).getClass();
                ((k0) obj2).c(i << 3, Long.valueOf(iIntValue2));
            }
        }
        if (i2 != size) {
            list.subList(i2, size).clear();
        }
        return obj2;
    }

    public static void k(j0 j0Var, Object obj, Object obj2) {
        ((l0) j0Var).getClass();
        AbstractC4027v abstractC4027v = (AbstractC4027v) obj;
        k0 k0Var = abstractC4027v.unknownFields;
        k0 k0Var2 = ((AbstractC4027v) obj2).unknownFields;
        k0 k0Var3 = k0.f;
        if (!k0Var3.equals(k0Var2)) {
            if (k0Var3.equals(k0Var)) {
                int i = k0Var.a + k0Var2.a;
                int[] iArrCopyOf = Arrays.copyOf(k0Var.b, i);
                System.arraycopy(k0Var2.b, 0, iArrCopyOf, k0Var.a, k0Var2.a);
                Object[] objArrCopyOf = Arrays.copyOf(k0Var.c, i);
                System.arraycopy(k0Var2.c, 0, objArrCopyOf, k0Var.a, k0Var2.a);
                k0Var = new k0(i, iArrCopyOf, objArrCopyOf, true);
            } else {
                k0Var.getClass();
                if (!k0Var2.equals(k0Var3)) {
                    if (!k0Var.e) {
                        throw new UnsupportedOperationException();
                    }
                    int i2 = k0Var.a + k0Var2.a;
                    k0Var.a(i2);
                    System.arraycopy(k0Var2.b, 0, k0Var.b, k0Var.a, k0Var2.a);
                    System.arraycopy(k0Var2.c, 0, k0Var.c, k0Var.a, k0Var2.a);
                    k0Var.a = i2;
                }
            }
        }
        abstractC4027v.unknownFields = k0Var;
    }

    public static boolean l(Object obj, Object obj2) {
        if (obj != obj2) {
            return obj != null && obj.equals(obj2);
        }
        return true;
    }

    public static void m(int i, List list, K k, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        AbstractC4018l abstractC4018l = (AbstractC4018l) k.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                abstractC4018l.o(i, ((Boolean) list.get(i2)).booleanValue());
                i2++;
            }
            return;
        }
        abstractC4018l.C(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Boolean) list.get(i4)).getClass();
            Logger logger = AbstractC4018l.d;
            i3++;
        }
        abstractC4018l.E(i3);
        while (i2 < list.size()) {
            abstractC4018l.n(((Boolean) list.get(i2)).booleanValue() ? (byte) 1 : (byte) 0);
            i2++;
        }
    }

    public static void n(int i, List list, K k, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        AbstractC4018l abstractC4018l = (AbstractC4018l) k.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                double dDoubleValue = ((Double) list.get(i2)).doubleValue();
                abstractC4018l.getClass();
                abstractC4018l.u(i, Double.doubleToRawLongBits(dDoubleValue));
                i2++;
            }
            return;
        }
        abstractC4018l.C(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Double) list.get(i4)).getClass();
            Logger logger = AbstractC4018l.d;
            i3 += 8;
        }
        abstractC4018l.E(i3);
        while (i2 < list.size()) {
            abstractC4018l.v(Double.doubleToRawLongBits(((Double) list.get(i2)).doubleValue()));
            i2++;
        }
    }

    public static void o(int i, List list, K k, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        AbstractC4018l abstractC4018l = (AbstractC4018l) k.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                abstractC4018l.w(i, ((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        abstractC4018l.C(i, 2);
        int iL = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iL += AbstractC4018l.l(((Integer) list.get(i3)).intValue());
        }
        abstractC4018l.E(iL);
        while (i2 < list.size()) {
            abstractC4018l.x(((Integer) list.get(i2)).intValue());
            i2++;
        }
    }

    public static void p(int i, List list, K k, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        AbstractC4018l abstractC4018l = (AbstractC4018l) k.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                abstractC4018l.s(i, ((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        abstractC4018l.C(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Integer) list.get(i4)).getClass();
            Logger logger = AbstractC4018l.d;
            i3 += 4;
        }
        abstractC4018l.E(i3);
        while (i2 < list.size()) {
            abstractC4018l.t(((Integer) list.get(i2)).intValue());
            i2++;
        }
    }

    public static void q(int i, List list, K k, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        AbstractC4018l abstractC4018l = (AbstractC4018l) k.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                abstractC4018l.u(i, ((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        abstractC4018l.C(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Long) list.get(i4)).getClass();
            Logger logger = AbstractC4018l.d;
            i3 += 8;
        }
        abstractC4018l.E(i3);
        while (i2 < list.size()) {
            abstractC4018l.v(((Long) list.get(i2)).longValue());
            i2++;
        }
    }

    public static void r(int i, List list, K k, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        AbstractC4018l abstractC4018l = (AbstractC4018l) k.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                float fFloatValue = ((Float) list.get(i2)).floatValue();
                abstractC4018l.getClass();
                abstractC4018l.s(i, Float.floatToRawIntBits(fFloatValue));
                i2++;
            }
            return;
        }
        abstractC4018l.C(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Float) list.get(i4)).getClass();
            Logger logger = AbstractC4018l.d;
            i3 += 4;
        }
        abstractC4018l.E(i3);
        while (i2 < list.size()) {
            abstractC4018l.t(Float.floatToRawIntBits(((Float) list.get(i2)).floatValue()));
            i2++;
        }
    }

    public static void s(int i, List list, K k, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        AbstractC4018l abstractC4018l = (AbstractC4018l) k.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                abstractC4018l.w(i, ((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        abstractC4018l.C(i, 2);
        int iL = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iL += AbstractC4018l.l(((Integer) list.get(i3)).intValue());
        }
        abstractC4018l.E(iL);
        while (i2 < list.size()) {
            abstractC4018l.x(((Integer) list.get(i2)).intValue());
            i2++;
        }
    }

    public static void t(int i, List list, K k, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        AbstractC4018l abstractC4018l = (AbstractC4018l) k.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                abstractC4018l.F(i, ((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        abstractC4018l.C(i, 2);
        int iL = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iL += AbstractC4018l.l(((Long) list.get(i3)).longValue());
        }
        abstractC4018l.E(iL);
        while (i2 < list.size()) {
            abstractC4018l.G(((Long) list.get(i2)).longValue());
            i2++;
        }
    }

    public static void u(int i, List list, K k, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        AbstractC4018l abstractC4018l = (AbstractC4018l) k.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                abstractC4018l.s(i, ((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        abstractC4018l.C(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Integer) list.get(i4)).getClass();
            Logger logger = AbstractC4018l.d;
            i3 += 4;
        }
        abstractC4018l.E(i3);
        while (i2 < list.size()) {
            abstractC4018l.t(((Integer) list.get(i2)).intValue());
            i2++;
        }
    }

    public static void v(int i, List list, K k, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        AbstractC4018l abstractC4018l = (AbstractC4018l) k.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                abstractC4018l.u(i, ((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        abstractC4018l.C(i, 2);
        int i3 = 0;
        for (int i4 = 0; i4 < list.size(); i4++) {
            ((Long) list.get(i4)).getClass();
            Logger logger = AbstractC4018l.d;
            i3 += 8;
        }
        abstractC4018l.E(i3);
        while (i2 < list.size()) {
            abstractC4018l.v(((Long) list.get(i2)).longValue());
            i2++;
        }
    }

    public static void w(int i, List list, K k, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        AbstractC4018l abstractC4018l = (AbstractC4018l) k.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                int iIntValue = ((Integer) list.get(i2)).intValue();
                abstractC4018l.D(i, (iIntValue >> 31) ^ (iIntValue << 1));
                i2++;
            }
            return;
        }
        abstractC4018l.C(i, 2);
        int iK = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            int iIntValue2 = ((Integer) list.get(i3)).intValue();
            iK += AbstractC4018l.k((iIntValue2 >> 31) ^ (iIntValue2 << 1));
        }
        abstractC4018l.E(iK);
        while (i2 < list.size()) {
            int iIntValue3 = ((Integer) list.get(i2)).intValue();
            abstractC4018l.E((iIntValue3 >> 31) ^ (iIntValue3 << 1));
            i2++;
        }
    }

    public static void x(int i, List list, K k, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        AbstractC4018l abstractC4018l = (AbstractC4018l) k.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                long jLongValue = ((Long) list.get(i2)).longValue();
                abstractC4018l.F(i, (jLongValue >> 63) ^ (jLongValue << 1));
                i2++;
            }
            return;
        }
        abstractC4018l.C(i, 2);
        int iL = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            long jLongValue2 = ((Long) list.get(i3)).longValue();
            iL += AbstractC4018l.l((jLongValue2 >> 63) ^ (jLongValue2 << 1));
        }
        abstractC4018l.E(iL);
        while (i2 < list.size()) {
            long jLongValue3 = ((Long) list.get(i2)).longValue();
            abstractC4018l.G((jLongValue3 >> 63) ^ (jLongValue3 << 1));
            i2++;
        }
    }

    public static void y(int i, List list, K k, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        AbstractC4018l abstractC4018l = (AbstractC4018l) k.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                abstractC4018l.D(i, ((Integer) list.get(i2)).intValue());
                i2++;
            }
            return;
        }
        abstractC4018l.C(i, 2);
        int iK = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iK += AbstractC4018l.k(((Integer) list.get(i3)).intValue());
        }
        abstractC4018l.E(iK);
        while (i2 < list.size()) {
            abstractC4018l.E(((Integer) list.get(i2)).intValue());
            i2++;
        }
    }

    public static void z(int i, List list, K k, boolean z) {
        if (list == null || list.isEmpty()) {
            return;
        }
        AbstractC4018l abstractC4018l = (AbstractC4018l) k.a;
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                abstractC4018l.F(i, ((Long) list.get(i2)).longValue());
                i2++;
            }
            return;
        }
        abstractC4018l.C(i, 2);
        int iL = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iL += AbstractC4018l.l(((Long) list.get(i3)).longValue());
        }
        abstractC4018l.E(iL);
        while (i2 < list.size()) {
            abstractC4018l.G(((Long) list.get(i2)).longValue());
            i2++;
        }
    }
}
