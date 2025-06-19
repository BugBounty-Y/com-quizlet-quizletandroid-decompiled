package androidx.compose.foundation.lazy.layout;

import androidx.appcompat.widget.C0122z;
import androidx.compose.animation.core.D0;
import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.layout.C0419y;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.L0;
import androidx.compose.runtime.X0;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.ranges.IntRange;

/* renamed from: androidx.compose.foundation.lazy.layout.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0448u {
    public static final E[] a = new E[0];

    public static final void a(kotlin.reflect.k kVar, androidx.compose.ui.q qVar, c0 c0Var, Function2 function2, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2002163445);
        if ((((c0814p.h(kVar) ? 4 : 2) | i | (c0814p.f(qVar) ? 32 : 16) | (c0814p.f(c0Var) ? 256 : 128) | (c0814p.h(function2) ? 2048 : 1024)) & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            c(androidx.compose.runtime.internal.e.e(-1488997347, new S(c0Var, qVar, function2, C0776c.D(kVar, c0814p)), c0814p), c0814p, 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new T(kVar, qVar, c0Var, function2, i);
        }
    }

    public static final void b(Object obj, int i, Z z, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2079116560);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.h(obj) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p.d(i) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p.h(z) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p.h(dVar) ? 2048 : 1024;
        }
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            boolean zF = c0814p.f(obj) | c0814p.f(z);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (zF || objI == v) {
                objI = new Y(obj, z);
                c0814p.i0(objI);
            }
            Y y = (Y) objI;
            y.c.j(i);
            androidx.compose.runtime.B b = androidx.compose.ui.layout.U.a;
            Y y2 = (Y) c0814p.j(b);
            androidx.compose.runtime.snapshots.h hVarD = androidx.compose.runtime.snapshots.r.d();
            Function1 function1E = hVarD != null ? hVarD.e() : null;
            androidx.compose.runtime.snapshots.h hVarE = androidx.compose.runtime.snapshots.r.e(hVarD);
            InterfaceC0773a0 interfaceC0773a0 = y.f;
            try {
                if (y2 != ((Y) ((L0) interfaceC0773a0).getValue())) {
                    ((L0) interfaceC0773a0).setValue(y2);
                    if (y.a() > 0) {
                        InterfaceC0773a0 interfaceC0773a02 = y.e;
                        Y y3 = (Y) ((L0) interfaceC0773a02).getValue();
                        if (y3 != null) {
                            y3.c();
                        }
                        if (y2 != null) {
                            y2.b();
                        } else {
                            y2 = null;
                        }
                        ((L0) interfaceC0773a02).setValue(y2);
                    }
                }
                Unit unit = Unit.a;
                androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
                boolean zF2 = c0814p.f(y);
                Object objI2 = c0814p.I();
                if (zF2 || objI2 == v) {
                    objI2 = new androidx.camera.lifecycle.f(y, 17);
                    c0814p.i0(objI2);
                }
                C0776c.d(y, (Function1) objI2, c0814p);
                C0776c.a(b.a(y), dVar, c0814p, ((i3 >> 6) & ContentType.LONG_FORM_ON_DEMAND) | 8);
            } catch (Throwable th) {
                androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
                throw th;
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0419y(obj, i, z, dVar, i2);
        }
    }

    public static final void c(androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2 = 3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(674185128);
        if ((i & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            X0 x0 = androidx.compose.runtime.saveable.k.a;
            androidx.compose.runtime.saveable.i iVar = (androidx.compose.runtime.saveable.i) c0814p.j(x0);
            Object[] objArr = {iVar};
            k0 k0Var = k0.a;
            j0 j0Var = new j0(iVar, 1);
            com.quizlet.data.repository.explanations.myexplanations.a aVar = androidx.compose.runtime.saveable.m.a;
            com.quizlet.data.repository.explanations.myexplanations.a aVar2 = new com.quizlet.data.repository.explanations.myexplanations.a(k0Var, false, j0Var, i2);
            boolean zH = c0814p.h(iVar);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new androidx.compose.animation.core.K(iVar, 7);
                c0814p.i0(objI);
            }
            l0 l0Var = (l0) L4.d(objArr, aVar2, (Function0) objI, c0814p, 0, 4);
            C0776c.a(x0.a(l0Var), androidx.compose.runtime.internal.e.e(1863926504, new androidx.compose.foundation.contextmenu.i(8, l0Var, dVar), c0814p), c0814p, 56);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.layout.W(dVar, i, 2);
        }
    }

    public static final void d(N n, Object obj, int i, Object obj2, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1439843069);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.f(n) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p.f(obj) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p.d(i) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p.f(obj2) ? 2048 : 1024;
        }
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            ((androidx.compose.runtime.saveable.c) obj).e(obj2, androidx.compose.runtime.internal.e.e(980966366, new D0(n, i, obj2, 4), c0814p), c0814p, 48);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0419y(n, obj, i, obj2, i2);
        }
    }

    public static final int e(int i, androidx.compose.runtime.collection.b bVar) {
        int i2 = bVar.c - 1;
        int i3 = 0;
        while (i3 < i2) {
            int i4 = ((i2 - i3) / 2) + i3;
            Object[] objArr = bVar.a;
            int i5 = ((C0435g) objArr[i4]).a;
            if (i5 != i) {
                if (i5 < i) {
                    i3 = i4 + 1;
                    if (i < ((C0435g) objArr[i3]).a) {
                    }
                } else {
                    i2 = i4 - 1;
                }
            }
            return i4;
        }
        return i3;
    }

    public static final List f(N n, Z z, com.airbnb.lottie.network.d dVar) {
        IntRange intRange;
        if (!((androidx.compose.runtime.collection.b) dVar.b).m() && z.a.isEmpty()) {
            return kotlin.collections.K.a;
        }
        ArrayList arrayList = new ArrayList();
        androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) dVar.b;
        if (bVar.m()) {
            int i = bVar.c;
            if (i == 0) {
                throw new NoSuchElementException("MutableVector is empty.");
            }
            Object[] objArr = bVar.a;
            int i2 = ((C0442n) objArr[0]).a;
            if (i > 0) {
                int i3 = 0;
                do {
                    int i4 = ((C0442n) objArr[i3]).a;
                    if (i4 < i2) {
                        i2 = i4;
                    }
                    i3++;
                } while (i3 < i);
            }
            if (i2 < 0) {
                throw new IllegalArgumentException("negative minIndex");
            }
            int i5 = bVar.c;
            if (i5 == 0) {
                throw new NoSuchElementException("MutableVector is empty.");
            }
            Object[] objArr2 = bVar.a;
            int i6 = ((C0442n) objArr2[0]).b;
            if (i5 > 0) {
                int i7 = 0;
                do {
                    int i8 = ((C0442n) objArr2[i7]).b;
                    if (i8 > i6) {
                        i6 = i8;
                    }
                    i7++;
                } while (i7 < i5);
            }
            intRange = new IntRange(i2, Math.min(i6, n.d() - 1), 1);
        } else {
            IntRange.e.getClass();
            intRange = IntRange.f;
        }
        int size = z.a.size();
        for (int i9 = 0; i9 < size; i9++) {
            Y y = (Y) z.get(i9);
            int iH = h(n, y.a, y.c.i());
            int i10 = intRange.a;
            if ((iH > intRange.b || i10 > iH) && iH >= 0 && iH < n.d()) {
                arrayList.add(Integer.valueOf(iH));
            }
        }
        int i11 = intRange.a;
        int i12 = intRange.b;
        if (i11 <= i12) {
            while (true) {
                arrayList.add(Integer.valueOf(i11));
                if (i11 == i12) {
                    break;
                }
                i11++;
            }
        }
        return arrayList;
    }

    public static InterfaceC0773a0 g() {
        return C0776c.y(Unit.a, androidx.compose.runtime.V.c);
    }

    public static final int h(N n, Object obj, int i) {
        int iA;
        return (obj == null || n.d() == 0 || (i < n.d() && obj.equals(n.b(i))) || (iA = n.a(obj)) == -1) ? i : iA;
    }

    public static final void l(InterfaceC0773a0 interfaceC0773a0) {
        interfaceC0773a0.setValue(Unit.a);
    }

    public static final androidx.compose.ui.q m(androidx.compose.ui.q qVar, r rVar, com.airbnb.lottie.network.d dVar, androidx.compose.ui.unit.k kVar, EnumC0320d0 enumC0320d0, boolean z, InterfaceC0806l interfaceC0806l, int i) {
        if (!z) {
            C0814p c0814p = (C0814p) interfaceC0806l;
            c0814p.X(-1890658823);
            c0814p.p(false);
            return qVar;
        }
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.X(-1890632411);
        boolean z2 = true;
        boolean z3 = ((((i & ContentType.LONG_FORM_ON_DEMAND) ^ 48) > 32 && c0814p2.f(rVar)) || (i & 48) == 32) | ((((i & 896) ^ 384) > 256 && c0814p2.f(dVar)) || (i & 384) == 256) | ((((i & 7168) ^ 3072) > 2048 && c0814p2.g(false)) || (i & 3072) == 2048) | ((((57344 & i) ^ 24576) > 16384 && c0814p2.f(kVar)) || (i & 24576) == 16384);
        if ((((458752 & i) ^ 196608) <= 131072 || !c0814p2.f(enumC0320d0)) && (i & 196608) != 131072) {
            z2 = false;
        }
        boolean z4 = z3 | z2;
        Object objI = c0814p2.I();
        if (z4 || objI == C0804k.a) {
            objI = new C0445q(rVar, dVar, kVar, enumC0320d0);
            c0814p2.i0(objI);
        }
        androidx.compose.ui.q qVarG = qVar.g((C0445q) objI);
        c0814p2.p(false);
        return qVarG;
    }

    public static final androidx.compose.ui.q n(androidx.compose.ui.q qVar, kotlin.reflect.k kVar, e0 e0Var, EnumC0320d0 enumC0320d0, boolean z) {
        return qVar.g(new LazyLayoutSemanticsModifier(kVar, e0Var, enumC0320d0, z));
    }

    public Object i(int i) {
        C0435g c0435gO = j().o(i);
        return c0435gO.c.getType().invoke(Integer.valueOf(i - c0435gO.a));
    }

    public abstract C0122z j();

    public Object k(int i) {
        Object objInvoke;
        C0435g c0435gO = j().o(i);
        int i2 = i - c0435gO.a;
        Function1 key = c0435gO.c.getKey();
        return (key == null || (objInvoke = key.invoke(Integer.valueOf(i2))) == null) ? new DefaultLazyKey(i) : objInvoke;
    }
}
