package androidx.collection;

import java.util.ConcurrentModificationException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class r {
    public static final Object a = new Object();
    public static final Object b = new Object();

    public static final void a(W w) {
        int i = w.d;
        int[] iArr = w.b;
        Object[] objArr = w.c;
        int i2 = 0;
        for (int i3 = 0; i3 < i; i3++) {
            Object obj = objArr[i3];
            if (obj != b) {
                if (i3 != i2) {
                    iArr[i2] = iArr[i3];
                    objArr[i2] = obj;
                    objArr[i3] = null;
                }
                i2++;
            }
        }
        w.a = false;
        w.d = i2;
    }

    public static final void b(C0209g c0209g, int i) {
        Intrinsics.checkNotNullParameter(c0209g, "<this>");
        int[] iArr = new int[i];
        c0209g.getClass();
        Intrinsics.checkNotNullParameter(iArr, "<set-?>");
        c0209g.a = iArr;
        Object[] objArr = new Object[i];
        Intrinsics.checkNotNullParameter(objArr, "<set-?>");
        c0209g.b = objArr;
    }

    public static final int c(C0209g c0209g, Object obj, int i) {
        Intrinsics.checkNotNullParameter(c0209g, "<this>");
        int i2 = c0209g.c;
        if (i2 == 0) {
            return -1;
        }
        Intrinsics.checkNotNullParameter(c0209g, "<this>");
        try {
            int iA = androidx.collection.internal.a.a(c0209g.c, i, c0209g.a);
            if (iA < 0 || Intrinsics.b(obj, c0209g.b[iA])) {
                return iA;
            }
            int i3 = iA + 1;
            while (i3 < i2 && c0209g.a[i3] == i) {
                if (Intrinsics.b(obj, c0209g.b[i3])) {
                    return i3;
                }
                i3++;
            }
            for (int i4 = iA - 1; i4 >= 0 && c0209g.a[i4] == i; i4--) {
                if (Intrinsics.b(obj, c0209g.b[i4])) {
                    return i4;
                }
            }
            return ~i3;
        } catch (IndexOutOfBoundsException unused) {
            throw new ConcurrentModificationException();
        }
    }
}
