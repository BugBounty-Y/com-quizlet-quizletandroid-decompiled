package androidx.compose.runtime;

import androidx.collection.C0223v;
import java.util.ArrayList;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public abstract class r {
    public static final C0791d0 a = new C0791d0("provider");
    public static final C0791d0 b = new C0791d0("provider");
    public static final C0791d0 c = new C0791d0("compositionLocalMap");
    public static final C0791d0 d = new C0791d0("providers");
    public static final C0791d0 e = new C0791d0("reference");
    public static final androidx.camera.camera2.internal.a0 f = new androidx.camera.camera2.internal.a0(2);

    public static final void a(ArrayList arrayList, int i, int i2) {
        int iG = g(i, arrayList);
        if (iG < 0) {
            iG = -(iG + 1);
        }
        while (iG < arrayList.size() && ((O) arrayList.get(iG)).b < i2) {
            arrayList.remove(iG);
        }
    }

    public static final void b(C0840z0 c0840z0, ArrayList arrayList, int i) {
        if (c0840z0.j(i)) {
            arrayList.add(c0840z0.l(i));
            return;
        }
        int[] iArr = c0840z0.b;
        int i2 = iArr[(i * 5) + 3] + i;
        for (int i3 = i + 1; i3 < i2; i3 += iArr[(i3 * 5) + 3]) {
            b(c0840z0, arrayList, i3);
        }
    }

    public static final void c(@NotNull String str) {
        throw new ComposeRuntimeError(android.support.v4.media.session.a.B("Compose Runtime internal error. Unexpected or incorrect use of the Compose internal runtime API (", str, "). Please report to Google or use https://goo.gle/compose-feedback"));
    }

    @NotNull
    public static final Void d(@NotNull String str) {
        throw new ComposeRuntimeError(android.support.v4.media.session.a.B("Compose Runtime internal error. Unexpected or incorrect use of the Compose internal runtime API (", str, "). Please report to Google or use https://goo.gle/compose-feedback"));
    }

    public static final void e(D0 d0, androidx.compose.runtime.internal.j jVar) {
        int iO;
        int[] iArr = d0.b;
        int i = d0.t;
        int iF = d0.f(iArr, d0.q(d0.s(i) + i));
        for (int iF2 = d0.f(d0.b, d0.q(d0.t)); iF2 < iF; iF2++) {
            Object obj = d0.c[d0.g(iF2)];
            int iC = -1;
            if (obj instanceof InterfaceC0802j) {
                jVar.w((InterfaceC0802j) obj, d0.o() - iF2, -1, -1);
            } else if (obj instanceof C0836x0) {
                C0836x0 c0836x0 = (C0836x0) obj;
                if (!(c0836x0.a instanceof C0808m)) {
                    i(d0, iF2, obj);
                    int iO2 = d0.o() - iF2;
                    C0774b c0774b = c0836x0.b;
                    if (c0774b == null || !c0774b.a()) {
                        iO = -1;
                    } else {
                        iC = d0.c(c0774b);
                        iO = d0.o() - d0.O(iC);
                    }
                    jVar.w(c0836x0, iO2, iC, iO);
                }
            } else if (obj instanceof C0813o0) {
                i(d0, iF2, obj);
                ((C0813o0) obj).d();
            }
        }
    }

    public static final Y f(C0833w c0833w, Z z, D0 d0, InterfaceC0790d interfaceC0790d) {
        A0 a0 = new A0();
        if (d0.e != null) {
            a0.b();
        }
        if (d0.f != null) {
            a0.k = new C0223v();
        }
        int i = d0.t;
        if (interfaceC0790d != null && d0.D(i) > 0) {
            int iE = d0.v;
            while (iE > 0 && !d0.w(iE)) {
                iE = d0.E(d0.b, iE);
            }
            if (iE >= 0 && d0.w(iE)) {
                Object objC = d0.C(iE);
                int i2 = iE + 1;
                int iS = d0.s(iE) + iE;
                int iD = 0;
                while (i2 < iS) {
                    int iS2 = d0.s(i2) + i2;
                    if (iS2 > i) {
                        break;
                    }
                    iD += d0.w(i2) ? 1 : d0.D(i2);
                    i2 = iS2;
                }
                int iD2 = d0.w(i) ? 1 : d0.D(i);
                interfaceC0790d.d(objC);
                interfaceC0790d.f(iD, iD2);
                interfaceC0790d.h();
            }
        }
        D0 d0G = a0.g();
        try {
            d0G.d();
            X x = z.a;
            V v = C0804k.a;
            d0G.Q(x, false, v, 126665345);
            D0.x(d0G);
            d0G.S(z.b);
            List listB = d0.B(z.e, d0G);
            d0G.K();
            d0G.i();
            d0G.j();
            d0G.e(true);
            Y y = new Y(a0);
            if (!listB.isEmpty()) {
                int size = listB.size();
                for (int i3 = 0; i3 < size; i3++) {
                    C0774b c0774b = (C0774b) listB.get(i3);
                    if (a0.h(c0774b)) {
                        int iA = a0.a(c0774b);
                        int iC = C0.c(a0.a, iA);
                        int i4 = iA + 1;
                        if (((i4 < a0.b ? a0.a[(i4 * 5) + 4] : a0.c.length) - iC > 0 ? a0.c[iC] : v) instanceof C0813o0) {
                            C0816q c0816q = new C0816q(c0833w, z);
                            d0G = a0.g();
                            try {
                                C0776c.k(d0G, listB, c0816q);
                                Unit unit = Unit.a;
                                d0G.e(true);
                                return y;
                            } finally {
                            }
                        }
                    }
                }
            }
            return y;
        } finally {
        }
    }

    public static final int g(int i, ArrayList arrayList) {
        int size = arrayList.size() - 1;
        int i2 = 0;
        while (i2 <= size) {
            int i3 = (i2 + size) >>> 1;
            int iG = Intrinsics.g(((O) arrayList.get(i3)).b, i);
            if (iG < 0) {
                i2 = i3 + 1;
            } else {
                if (iG <= 0) {
                    return i3;
                }
                size = i3 - 1;
            }
        }
        return -(i2 + 1);
    }

    public static final void h(D0 d0, androidx.compose.runtime.internal.j jVar) {
        int iO;
        int[] iArr = d0.b;
        int i = d0.t;
        int iF = d0.f(iArr, d0.q(d0.s(i) + i));
        for (int iF2 = d0.f(d0.b, d0.q(d0.t)); iF2 < iF; iF2++) {
            Object obj = d0.c[d0.g(iF2)];
            int iC = -1;
            if (obj instanceof InterfaceC0802j) {
                int iO2 = d0.o() - iF2;
                Object obj2 = (InterfaceC0802j) obj;
                androidx.collection.J j = (androidx.collection.J) jVar.f;
                if (j == null) {
                    int i2 = androidx.collection.U.a;
                    j = new androidx.collection.J();
                    jVar.f = j;
                }
                j.b[j.d(obj2)] = obj2;
                jVar.w(obj2, iO2, -1, -1);
            }
            if (obj instanceof C0836x0) {
                int iO3 = d0.o() - iF2;
                C0836x0 c0836x0 = (C0836x0) obj;
                C0774b c0774b = c0836x0.b;
                if (c0774b == null || !c0774b.a()) {
                    iO = -1;
                } else {
                    iC = d0.c(c0774b);
                    iO = d0.o() - d0.O(iC);
                }
                jVar.w(c0836x0, iO3, iC, iO);
            }
            if (obj instanceof C0813o0) {
                ((C0813o0) obj).d();
            }
        }
        d0.H();
    }

    public static final void i(D0 d0, int i, Object obj) {
        int iG = d0.g(i);
        Object[] objArr = d0.c;
        Object obj2 = objArr[iG];
        objArr[iG] = C0804k.a;
        if (obj == obj2) {
            return;
        }
        c("Slot table is out of sync (expected " + obj + ", got " + obj2 + ')');
    }
}
