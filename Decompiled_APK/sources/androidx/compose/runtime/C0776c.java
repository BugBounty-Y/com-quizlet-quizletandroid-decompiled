package androidx.compose.runtime;

import androidx.collection.C0222u;
import androidx.compose.animation.C0281h;
import androidx.compose.material3.C0685m4;
import androidx.compose.runtime.changelist.C0778a;
import androidx.datastore.core.C1087t;
import com.google.android.gms.internal.mlkit_vision_barcode.D4;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.C4930v;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* renamed from: androidx.compose.runtime.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0776c {
    public static final Object a = new Object();
    public static final H b = new H();

    public static final InterfaceC0773a0 A(InterfaceC0806l interfaceC0806l, Object obj, Function2 function2) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        Object objI = c0814p.I();
        V v = C0804k.a;
        if (objI == v) {
            objI = z(obj);
            c0814p.i0(objI);
        }
        InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
        Unit unit = Unit.a;
        boolean zH = c0814p.h(function2);
        Object objI2 = c0814p.I();
        if (zH || objI2 == v) {
            objI2 = new O0(function2, interfaceC0773a0, null);
            c0814p.i0(objI2);
        }
        f(c0814p, unit, (Function2) objI2);
        return interfaceC0773a0;
    }

    public static final Object B(InterfaceC0803j0 interfaceC0803j0, AbstractC0809m0 abstractC0809m0) {
        Intrinsics.e(abstractC0809m0, "null cannot be cast to non-null type androidx.compose.runtime.CompositionLocal<kotlin.Any?>");
        Object objB = interfaceC0803j0.get(abstractC0809m0);
        if (objB == null) {
            objB = abstractC0809m0.b();
        }
        return ((Z0) objB).a(interfaceC0803j0);
    }

    public static final C0810n C(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.T(OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SERVICE_SPECIFIC_OFF, r.e);
        if (c0814p.O) {
            D0.x(c0814p.H);
        }
        Object objA = c0814p.A();
        C0808m c0808m = objA instanceof C0808m ? (C0808m) objA : null;
        if (c0808m == null) {
            c0808m = new C0808m(new C0810n(c0814p, c0814p.P, c0814p.p, c0814p.B, c0814p.g.r));
            c0814p.j0(c0808m);
        }
        InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
        C0810n c0810n = c0808m.a;
        ((L0) c0810n.f).setValue(interfaceC0803j0L);
        c0814p.p(false);
        return c0810n;
    }

    public static final InterfaceC0773a0 D(Object obj, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        Object objI = c0814p.I();
        if (objI == C0804k.a) {
            objI = z(obj);
            c0814p.i0(objI);
        }
        InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
        interfaceC0773a0.setValue(obj);
        return interfaceC0773a0;
    }

    public static final void E(InterfaceC0806l interfaceC0806l, Object obj, Function2 function2) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        if (c0814p.O || !Intrinsics.b(c0814p.I(), obj)) {
            c0814p.i0(obj);
            c0814p.b(obj, function2);
        }
    }

    public static final C1087t F(Function0 function0) {
        return new C1087t(new U0(function0, null));
    }

    public static final int G(C0222u c0222u) {
        int iC;
        int i = c0222u.b;
        int iC2 = c0222u.c(0);
        while (c0222u.b != 0 && c0222u.c(0) == iC2) {
            c0222u.g(0, c0222u.d());
            c0222u.f(c0222u.b - 1);
            int i2 = c0222u.b;
            int i3 = i2 >>> 1;
            int i4 = 0;
            while (i4 < i3) {
                int iC3 = c0222u.c(i4);
                int i5 = (i4 + 1) * 2;
                int i6 = i5 - 1;
                int iC4 = c0222u.c(i6);
                if (i5 >= i2 || (iC = c0222u.c(i5)) <= iC4) {
                    if (iC4 > iC3) {
                        c0222u.g(i4, iC4);
                        c0222u.g(i6, iC3);
                        i4 = i6;
                    }
                } else if (iC > iC3) {
                    c0222u.g(i4, iC);
                    c0222u.g(i5, iC3);
                    i4 = i5;
                }
            }
        }
        return iC2;
    }

    public static final int H(int i) {
        int i2 = 306783378 & i;
        int i3 = 613566756 & i;
        return (i & (-920350135)) | (i3 >> 1) | i2 | ((i2 << 1) & i3);
    }

    public static final androidx.compose.runtime.internal.i I(C0811n0[] c0811n0Arr, InterfaceC0803j0 interfaceC0803j0, InterfaceC0803j0 interfaceC0803j02) {
        androidx.compose.runtime.internal.i iVar = androidx.compose.runtime.internal.i.e;
        androidx.compose.runtime.internal.h hVar = new androidx.compose.runtime.internal.h(iVar);
        hVar.g = iVar;
        for (C0811n0 c0811n0 : c0811n0Arr) {
            AbstractC0809m0 abstractC0809m0 = c0811n0.a;
            if (c0811n0.f || !interfaceC0803j0.containsKey(abstractC0809m0)) {
                hVar.put(abstractC0809m0, abstractC0809m0.c(c0811n0, (Z0) interfaceC0803j02.get(abstractC0809m0)));
            }
        }
        return hVar.build();
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0048  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x009d  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00c9  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x00f9  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0104  */
    /* JADX WARN: Removed duplicated region for block: B:56:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(androidx.compose.runtime.C0811n0 r10, kotlin.jvm.functions.Function2 r11, androidx.compose.runtime.InterfaceC0806l r12, int r13) {
        /*
            Method dump skipped, instructions count: 270
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0776c.a(androidx.compose.runtime.n0, kotlin.jvm.functions.Function2, androidx.compose.runtime.l, int):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:25:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x00b2  */
    /* JADX WARN: Removed duplicated region for block: B:30:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r1v4, types: [androidx.compose.runtime.j0, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r8v0, types: [java.lang.Object, kotlin.jvm.functions.Function2] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(androidx.compose.runtime.C0811n0[] r7, kotlin.jvm.functions.Function2 r8, androidx.compose.runtime.InterfaceC0806l r9, int r10) {
        /*
            androidx.compose.runtime.p r9 = (androidx.compose.runtime.C0814p) r9
            r0 = -1390796515(0xffffffffad1a211d, float:-8.761239E-12)
            r9.Z(r0)
            androidx.compose.runtime.j0 r0 = r9.l()
            androidx.compose.runtime.d0 r1 = androidx.compose.runtime.r.b
            r2 = 201(0xc9, float:2.82E-43)
            r9.T(r2, r1)
            boolean r1 = r9.O
            r2 = 0
            r3 = 1
            if (r1 == 0) goto L27
            androidx.compose.runtime.internal.i r1 = androidx.compose.runtime.internal.i.e
            androidx.compose.runtime.internal.i r1 = I(r7, r0, r1)
            androidx.compose.runtime.internal.i r0 = r9.h0(r0, r1)
            r9.I = r3
        L25:
            r1 = r2
            goto L74
        L27:
            androidx.compose.runtime.z0 r1 = r9.F
            int r4 = r1.g
            java.lang.Object r1 = r1.h(r4, r2)
            java.lang.String r4 = "null cannot be cast to non-null type androidx.compose.runtime.PersistentCompositionLocalMap"
            kotlin.jvm.internal.Intrinsics.e(r1, r4)
            androidx.compose.runtime.j0 r1 = (androidx.compose.runtime.InterfaceC0803j0) r1
            androidx.compose.runtime.z0 r5 = r9.F
            int r6 = r5.g
            java.lang.Object r5 = r5.h(r6, r3)
            kotlin.jvm.internal.Intrinsics.e(r5, r4)
            androidx.compose.runtime.j0 r5 = (androidx.compose.runtime.InterfaceC0803j0) r5
            androidx.compose.runtime.internal.i r4 = I(r7, r0, r5)
            boolean r6 = r9.x()
            if (r6 == 0) goto L65
            boolean r6 = r9.x
            if (r6 != 0) goto L65
            boolean r5 = r5.equals(r4)
            if (r5 != 0) goto L58
            goto L65
        L58:
            int r0 = r9.k
            androidx.compose.runtime.z0 r4 = r9.F
            int r4 = r4.q()
            int r4 = r4 + r0
            r9.k = r4
            r0 = r1
            goto L25
        L65:
            androidx.compose.runtime.internal.i r0 = r9.h0(r0, r4)
            boolean r4 = r9.x
            if (r4 != 0) goto L73
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r0, r1)
            if (r1 != 0) goto L25
        L73:
            r1 = r3
        L74:
            if (r1 == 0) goto L7d
            boolean r4 = r9.O
            if (r4 != 0) goto L7d
            r9.G(r0)
        L7d:
            boolean r4 = r9.v
            androidx.compose.runtime.N r5 = r9.w
            r5.c(r4)
            r9.v = r1
            r9.J = r0
            androidx.compose.runtime.d0 r1 = androidx.compose.runtime.r.c
            r4 = 202(0xca, float:2.83E-43)
            r9.R(r1, r4, r0, r2)
            int r0 = r10 >> 3
            r0 = r0 & 14
            java.lang.Integer r0 = java.lang.Integer.valueOf(r0)
            r8.invoke(r9, r0)
            r9.p(r2)
            r9.p(r2)
            int r0 = r5.b()
            if (r0 == 0) goto La7
            r2 = r3
        La7:
            r9.v = r2
            r0 = 0
            r9.J = r0
            androidx.compose.runtime.o0 r9 = r9.r()
            if (r9 == 0) goto Lbb
            androidx.compose.animation.core.D0 r0 = new androidx.compose.animation.core.D0
            r1 = 10
            r0.<init>(r7, r8, r10, r1)
            r9.d = r0
        Lbb:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0776c.b(androidx.compose.runtime.n0[], kotlin.jvm.functions.Function2, androidx.compose.runtime.l, int):void");
    }

    public static final void c(Object obj, Object obj2, Function1 function1, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        boolean zF = c0814p.f(obj) | c0814p.f(obj2);
        Object objI = c0814p.I();
        if (zF || objI == C0804k.a) {
            objI = new F(function1);
            c0814p.i0(objI);
        }
    }

    public static final void d(Object obj, Function1 function1, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        boolean zF = c0814p.f(obj);
        Object objI = c0814p.I();
        if (zF || objI == C0804k.a) {
            objI = new F(function1);
            c0814p.i0(objI);
        }
    }

    public static final void e(Object[] objArr, Function1 function1, InterfaceC0806l interfaceC0806l) {
        boolean zF = false;
        for (Object obj : Arrays.copyOf(objArr, objArr.length)) {
            zF |= ((C0814p) interfaceC0806l).f(obj);
        }
        C0814p c0814p = (C0814p) interfaceC0806l;
        Object objI = c0814p.I();
        if (zF || objI == C0804k.a) {
            c0814p.i0(new F(function1));
        }
    }

    public static final void f(InterfaceC0806l interfaceC0806l, Object obj, Function2 function2) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        CoroutineContext coroutineContextI = c0814p.b.i();
        boolean zF = c0814p.f(obj);
        Object objI = c0814p.I();
        if (zF || objI == C0804k.a) {
            objI = new T(coroutineContextI, function2);
            c0814p.i0(objI);
        }
    }

    public static final void g(Object obj, Object obj2, Function2 function2, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        CoroutineContext coroutineContextI = c0814p.b.i();
        boolean zF = c0814p.f(obj) | c0814p.f(obj2);
        Object objI = c0814p.I();
        if (zF || objI == C0804k.a) {
            objI = new T(coroutineContextI, function2);
            c0814p.i0(objI);
        }
    }

    public static final void h(Object[] objArr, Function2 function2, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        CoroutineContext coroutineContextI = c0814p.b.i();
        boolean zF = false;
        for (Object obj : Arrays.copyOf(objArr, objArr.length)) {
            zF |= c0814p.f(obj);
        }
        Object objI = c0814p.I();
        if (zF || objI == C0804k.a) {
            c0814p.i0(new T(coroutineContextI, function2));
        }
    }

    public static final void i(Function0 function0, InterfaceC0806l interfaceC0806l) {
        C0778a c0778a = ((C0814p) interfaceC0806l).L.b;
        c0778a.getClass();
        androidx.compose.runtime.changelist.B b2 = androidx.compose.runtime.changelist.B.c;
        androidx.compose.runtime.changelist.L l = c0778a.b;
        l.f(b2);
        D4.b(l, 0, function0);
    }

    public static final void j(C0222u c0222u, int i) {
        if (c0222u.b == 0 || !(c0222u.c(0) == i || c0222u.c(c0222u.b - 1) == i)) {
            int i2 = c0222u.b;
            c0222u.a(i);
            while (i2 > 0) {
                int i3 = ((i2 + 1) >>> 1) - 1;
                int iC = c0222u.c(i3);
                if (i <= iC) {
                    break;
                }
                c0222u.g(i2, iC);
                i2 = i3;
            }
            c0222u.g(i2, i);
        }
    }

    public static void k(D0 d0, List list, InterfaceC0815p0 interfaceC0815p0) {
        if (list.isEmpty()) {
            return;
        }
        int size = list.size();
        for (int i = 0; i < size; i++) {
            int iC = d0.c((C0774b) list.get(i));
            int iM = d0.M(d0.b, d0.q(iC));
            Object obj = iM < d0.f(d0.b, d0.q(iC + 1)) ? d0.c[d0.g(iM)] : C0804k.a;
            C0813o0 c0813o0 = obj instanceof C0813o0 ? (C0813o0) obj : null;
            if (c0813o0 != null) {
                c0813o0.b = interfaceC0815p0;
            }
        }
    }

    public static final InterfaceC0773a0 l(InterfaceC4992i interfaceC4992i, Object obj, CoroutineContext coroutineContext, InterfaceC0806l interfaceC0806l, int i, int i2) {
        if ((i2 & 2) != 0) {
            coroutineContext = kotlin.coroutines.n.a;
        }
        C0814p c0814p = (C0814p) interfaceC0806l;
        boolean zH = c0814p.h(coroutineContext) | c0814p.h(interfaceC4992i);
        Object objI = c0814p.I();
        V v = C0804k.a;
        if (zH || objI == v) {
            objI = new T0(coroutineContext, interfaceC4992i, null);
            c0814p.i0(objI);
        }
        Function2 function2 = (Function2) objI;
        Object objI2 = c0814p.I();
        if (objI2 == v) {
            objI2 = z(obj);
            c0814p.i0(objI2);
        }
        InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI2;
        boolean zH2 = c0814p.h(function2);
        Object objI3 = c0814p.I();
        if (zH2 || objI3 == v) {
            objI3 = new Q0(function2, interfaceC0773a0, null);
            c0814p.i0(objI3);
        }
        g(interfaceC4992i, coroutineContext, (Function2) objI3, c0814p);
        return interfaceC0773a0;
    }

    public static final InterfaceC0773a0 m(kotlinx.coroutines.flow.q0 q0Var, InterfaceC0806l interfaceC0806l) {
        return l(q0Var, q0Var.getValue(), kotlin.coroutines.n.a, interfaceC0806l, 0, 0);
    }

    public static final kotlinx.coroutines.C n(kotlin.coroutines.n nVar, InterfaceC0806l interfaceC0806l) {
        C5023i0 key = C5023i0.a;
        nVar.getClass();
        Intrinsics.checkNotNullParameter(key, "key");
        return new C0838y0(((C0814p) interfaceC0806l).b.i(), nVar);
    }

    public static final androidx.compose.runtime.collection.b o() {
        com.quizlet.data.repository.classfolder.e eVar = N0.b;
        androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) eVar.c();
        if (bVar != null) {
            return bVar;
        }
        androidx.compose.runtime.collection.b bVar2 = new androidx.compose.runtime.collection.b(new C0812o[0]);
        eVar.q(bVar2);
        return bVar2;
    }

    public static final E p(M0 m0, Function0 function0) {
        com.quizlet.data.repository.classfolder.e eVar = N0.a;
        return new E(m0, function0);
    }

    public static final E q(Function0 function0) {
        com.quizlet.data.repository.classfolder.e eVar = N0.a;
        return new E(null, function0);
    }

    public static final W r(CoroutineContext coroutineContext) {
        W w = (W) coroutineContext.get(V.b);
        if (w != null) {
            return w;
        }
        throw new IllegalStateException("A MonotonicFrameClock is not available in this CoroutineContext. Callers should supply an appropriate MonotonicFrameClock using withContext.");
    }

    public static final void s() {
        throw new IllegalStateException("Invalid applier");
    }

    public static final androidx.compose.runtime.internal.d t(androidx.compose.runtime.internal.d dVar) {
        return new androidx.compose.runtime.internal.d(true, -642339857, new C0281h(new X(new androidx.compose.runtime.internal.d(true, -514040016, new C0685m4(dVar, 1))), 20));
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static List u(D0 d0, int i, D0 d02, boolean z, boolean z2, boolean z3) {
        kotlin.collections.K k;
        boolean zI;
        C0774b c0774bR;
        int i2;
        int i3;
        int iS = d0.s(i);
        int i4 = i + iS;
        int iF = d0.f(d0.b, d0.q(i));
        int iF2 = d0.f(d0.b, d0.q(i4));
        int i5 = iF2 - iF;
        boolean z4 = i >= 0 && (d0.b[(d0.q(i) * 5) + 1] & 201326592) != 0;
        d02.u(iS);
        d02.v(i5, d02.t);
        if (d0.g < i4) {
            d0.z(i4);
        }
        if (d0.k < iF2) {
            d0.A(iF2, i4);
        }
        int[] iArr = d02.b;
        int i6 = d02.t;
        int i7 = i6 * 5;
        C4930v.e(i7, i * 5, i4 * 5, d0.b, iArr);
        Object[] objArr = d02.c;
        int i8 = d02.i;
        System.arraycopy(d0.c, iF, objArr, i8, i5);
        int i9 = d02.v;
        iArr[i7 + 2] = i9;
        int i10 = i6 - i;
        int i11 = i6 + iS;
        int iF3 = i8 - d02.f(iArr, i6);
        int i12 = d02.m;
        int i13 = d02.l;
        int length = objArr.length;
        boolean z5 = z4;
        int i14 = i12;
        int i15 = i6;
        while (i15 < i11) {
            if (i15 != i6) {
                int i16 = (i15 * 5) + 2;
                iArr[i16] = iArr[i16] + i10;
            }
            int[] iArr2 = iArr;
            int iF4 = d02.f(iArr, i15) + iF3;
            if (i14 < i15) {
                i2 = i6;
                i3 = 0;
            } else {
                i2 = i6;
                i3 = d02.k;
            }
            iArr2[(i15 * 5) + 4] = D0.h(iF4, i3, i13, length);
            if (i15 == i14) {
                i14++;
            }
            i15++;
            i6 = i2;
            iArr = iArr2;
        }
        int[] iArr3 = iArr;
        d02.m = i14;
        int iB = C0.b(d0.d, i, d0.n());
        int iB2 = C0.b(d0.d, i4, d0.n());
        if (iB < iB2) {
            ArrayList arrayList = d0.d;
            ArrayList arrayList2 = new ArrayList(iB2 - iB);
            for (int i17 = iB; i17 < iB2; i17++) {
                C0774b c0774b = (C0774b) arrayList.get(i17);
                c0774b.a += i10;
                arrayList2.add(c0774b);
            }
            d02.d.addAll(C0.b(d02.d, d02.t, d02.n()), arrayList2);
            arrayList.subList(iB, iB2).clear();
            k = arrayList2;
        } else {
            k = kotlin.collections.K.a;
        }
        if (!k.isEmpty()) {
            HashMap map = d0.e;
            HashMap map2 = d02.e;
            if (map != null && map2 != null) {
                int size = k.size();
                for (int i18 = 0; i18 < size; i18++) {
                }
            }
        }
        int i19 = d02.v;
        HashMap map3 = d02.e;
        if (map3 != null && (c0774bR = d02.R(i9)) != null) {
        }
        int iE = d0.E(d0.b, i);
        if (!z3) {
            zI = false;
        } else if (z) {
            boolean z6 = iE >= 0;
            if (z6) {
                d0.P();
                d0.a(iE - d0.t);
                d0.P();
            }
            d0.a(i - d0.t);
            boolean zH = d0.H();
            if (z6) {
                d0.L();
                d0.i();
                d0.L();
                d0.i();
            }
            zI = zH;
        } else {
            zI = d0.I(i, iS);
            d0.J(iF, i5, i - 1);
        }
        if (zI) {
            r.c("Unexpectedly removed anchors");
        }
        int i20 = d02.o;
        int i21 = iArr3[i7 + 1];
        d02.o = i20 + ((1073741824 & i21) == 0 ? i21 & 67108863 : 1);
        if (z2) {
            d02.t = i11;
            d02.i = i8 + i5;
        }
        if (z5) {
            d02.U(i9);
        }
        return k;
    }

    public static final F0 v(float f) {
        return new ParcelableSnapshotMutableFloatState(f);
    }

    public static final H0 w(int i) {
        return new ParcelableSnapshotMutableIntState(i);
    }

    public static final J0 x(long j) {
        return new ParcelableSnapshotMutableLongState(j);
    }

    public static final InterfaceC0773a0 y(Object obj, M0 m0) {
        return new ParcelableSnapshotMutableState(obj, m0);
    }

    public static InterfaceC0773a0 z(Object obj) {
        return new ParcelableSnapshotMutableState(obj, V.f);
    }
}
