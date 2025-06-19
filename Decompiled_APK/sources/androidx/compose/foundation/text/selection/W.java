package androidx.compose.foundation.text.selection;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.C0278e;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.K0;
import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.foundation.text.C0492h0;
import androidx.compose.foundation.text.u0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0844d;
import androidx.compose.ui.graphics.C0848h;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.InterfaceC0949j0;
import androidx.compose.ui.platform.S0;
import androidx.compose.ui.text.C0982b;
import androidx.compose.ui.text.C0995g;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3169i5;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class W {
    public static final androidx.compose.ui.geometry.c a = new androidx.compose.ui.geometry.c(Float.POSITIVE_INFINITY, Float.POSITIVE_INFINITY, Float.NEGATIVE_INFINITY, Float.NEGATIVE_INFINITY);
    public static C0848h b;
    public static C0844d c;
    public static androidx.compose.ui.graphics.drawscope.b d;

    public static final void a(InterfaceC0533n interfaceC0533n, androidx.compose.ui.d dVar, androidx.compose.runtime.internal.d dVar2, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(476043083);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(interfaceC0533n) : c0814p.h(interfaceC0533n) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(dVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(dVar2) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            boolean z = false;
            boolean z2 = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            if ((i2 & 14) == 4 || ((i2 & 8) != 0 && c0814p.f(interfaceC0533n))) {
                z = true;
            }
            boolean z3 = z2 | z;
            Object objI = c0814p.I();
            if (z3 || objI == C0804k.a) {
                objI = new C0529j(dVar, interfaceC0533n);
                c0814p.i0(objI);
            }
            androidx.compose.ui.window.l.a((C0529j) objI, null, new androidx.compose.ui.window.y(false, true, true, 1, false, false), dVar2, c0814p, ((i2 << 3) & 7168) | 384, 2);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.contextmenu.a(i, 4, interfaceC0533n, dVar, dVar2);
        }
    }

    public static final void b(androidx.compose.ui.n nVar, C0536q c0536q, Function1 function1, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2078139907);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(nVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(c0536q) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function1) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(dVar) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            b0 b0Var = (b0) L4.d(new Object[0], b0.l, C0542x.b, c0814p, 3072, 4);
            Object objI = c0814p.I();
            Object obj = C0804k.a;
            if (objI == obj) {
                objI = new U(b0Var);
                c0814p.i0(objI);
            }
            U u = (U) objI;
            u.e = (androidx.compose.ui.hapticfeedback.a) c0814p.j(AbstractC0955m0.j);
            u.f = (InterfaceC0949j0) c0814p.j(AbstractC0955m0.d);
            u.g = (S0) c0814p.j(AbstractC0955m0.o);
            u.d = new C0278e(28, u, function1);
            u.m(c0536q);
            AbstractC0484d0.d(u, androidx.compose.runtime.internal.e.e(-123806316, new androidx.compose.animation.N(b0Var, nVar, u, dVar, 1), c0814p), c0814p, 48);
            boolean zH = c0814p.h(u);
            Object objI2 = c0814p.I();
            if (zH || objI2 == obj) {
                objI2 = new C0541w(u, 0);
                c0814p.i0(objI2);
            }
            C0776c.d(u, (Function1) objI2, c0814p);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.contextmenu.b(nVar, c0536q, function1, dVar, i, 2);
        }
    }

    public static final void c(androidx.compose.ui.n nVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        androidx.compose.runtime.internal.d dVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1075498320);
        int i2 = (c0814p.f(nVar) ? 4 : 2) | i;
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
            dVar2 = dVar;
        } else {
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = C0776c.z(null);
                c0814p.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
            C0536q c0536q = (C0536q) interfaceC0773a0.getValue();
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = new androidx.compose.foundation.gestures.T(interfaceC0773a0, 6);
                c0814p.i0(objI2);
            }
            nVar2 = nVar;
            dVar2 = dVar;
            b(nVar2, c0536q, (Function1) objI2, dVar2, c0814p, (i2 & 14) | 3456);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.contextmenu.i(nVar2, dVar2, i, 9);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:73:0x00d1  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x00d3  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void d(androidx.compose.foundation.text.selection.InterfaceC0533n r17, boolean r18, androidx.compose.ui.text.style.h r19, boolean r20, long r21, androidx.compose.ui.q r23, androidx.compose.runtime.InterfaceC0806l r24, int r25) {
        /*
            Method dump skipped, instructions count: 325
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.W.d(androidx.compose.foundation.text.selection.n, boolean, androidx.compose.ui.text.style.h, boolean, long, androidx.compose.ui.q, androidx.compose.runtime.l, int):void");
    }

    public static final void e(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0, boolean z) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2111672474);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if (((i2 | (c0814p.h(function0) ? 32 : 16) | (c0814p.g(z) ? 256 : 128)) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC0382e.f(c0814p, androidx.compose.ui.a.a(K0.l(qVar, H.a, H.b), new C0527h(z, 0, function0)));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0525f(z, qVar, function0, i);
        }
    }

    public static final void f(androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2105228848);
        if ((((c0814p.f(qVar) ? 4 : 2) | i) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            d0 d0Var = d0.a;
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, d0Var, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.animation.d0.w(6, dVar, c0814p, true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new e0(qVar, dVar, i, 0);
        }
    }

    public static final void g(boolean z, androidx.compose.ui.text.style.h hVar, i0 i0Var, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        boolean z2;
        androidx.compose.ui.text.style.h hVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1344558920);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(hVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(i0Var) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            z2 = z;
            hVar2 = hVar;
        } else {
            int i3 = i2 & 14;
            boolean zF = (i3 == 4) | c0814p.f(i0Var);
            Object objI = c0814p.I();
            Object obj = C0804k.a;
            if (zF || objI == obj) {
                objI = new S(i0Var, z);
                c0814p.i0(objI);
            }
            u0 u0Var = (u0) objI;
            boolean zH = c0814p.h(i0Var) | (i3 == 4);
            Object objI2 = c0814p.I();
            if (zH || objI2 == obj) {
                objI2 = new j0(i0Var, z);
                c0814p.i0(objI2);
            }
            InterfaceC0533n interfaceC0533n = (InterfaceC0533n) objI2;
            boolean zF2 = androidx.compose.ui.text.K.f(i0Var.l().b);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            boolean zH2 = c0814p.h(u0Var);
            Object objI3 = c0814p.I();
            if (zH2 || objI3 == obj) {
                objI3 = new k0(u0Var, null);
                c0814p.i0(objI3);
            }
            z2 = z;
            hVar2 = hVar;
            d(interfaceC0533n, z2, hVar2, zF2, 0L, androidx.compose.ui.input.pointer.v.a(nVar, u0Var, (Function2) objI3), c0814p, (i2 << 3) & 1008);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0525f(z2, hVar2, i0Var, i);
        }
    }

    public static final C0536q h(I i, InterfaceC0528i interfaceC0528i) {
        boolean z = i.j() == 1;
        return new C0536q(m(i.l(), z, true, i.m(), interfaceC0528i), m(i.i(), z, false, i.h(), interfaceC0528i), z);
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0040 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:20:0x004c  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r2v1, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:16:0x003e -> B:18:0x0041). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object i(androidx.compose.ui.input.pointer.z r7, kotlin.coroutines.jvm.internal.a r8) {
        /*
            boolean r0 = r8 instanceof androidx.compose.foundation.text.selection.C0544z
            if (r0 == 0) goto L13
            r0 = r8
            androidx.compose.foundation.text.selection.z r0 = (androidx.compose.foundation.text.selection.C0544z) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            androidx.compose.foundation.text.selection.z r0 = new androidx.compose.foundation.text.selection.z
            r0.<init>(r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.compose.ui.input.pointer.z r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L41
        L29:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r8)
        L34:
            androidx.compose.ui.input.pointer.g r8 = androidx.compose.ui.input.pointer.g.b
            r0.j = r7
            r0.l = r3
            java.lang.Object r8 = r7.c(r8, r0)
            if (r8 != r1) goto L41
            return r1
        L41:
            androidx.compose.ui.input.pointer.f r8 = (androidx.compose.ui.input.pointer.f) r8
            java.lang.Object r2 = r8.a
            int r4 = r2.size()
            r5 = 0
        L4a:
            if (r5 >= r4) goto L5c
            java.lang.Object r6 = r2.get(r5)
            androidx.compose.ui.input.pointer.n r6 = (androidx.compose.ui.input.pointer.n) r6
            boolean r6 = androidx.compose.ui.input.pointer.l.a(r6)
            if (r6 != 0) goto L59
            goto L34
        L59:
            int r5 = r5 + 1
            goto L4a
        L5c:
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.W.i(androidx.compose.ui.input.pointer.z, kotlin.coroutines.jvm.internal.a):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:35:0x00b3  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00f3  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0014  */
    /* JADX WARN: Type inference failed for: r11v5, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r12v5, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r14v1, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r3v1, types: [java.lang.Object, java.util.List] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object j(androidx.compose.ui.input.pointer.z r11, androidx.compose.foundation.text.selection.InterfaceC0530k r12, androidx.appcompat.widget.C0122z r13, androidx.compose.ui.input.pointer.f r14, kotlin.coroutines.jvm.internal.a r15) {
        /*
            Method dump skipped, instructions count: 278
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.W.j(androidx.compose.ui.input.pointer.z, androidx.compose.foundation.text.selection.k, androidx.appcompat.widget.z, androidx.compose.ui.input.pointer.f, kotlin.coroutines.jvm.internal.a):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:38:0x00aa, code lost:
    
        if (r14 == r2) goto L39;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0014  */
    /* JADX WARN: Type inference failed for: r11v7, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r13v1, types: [java.lang.Object, java.util.List] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object k(androidx.compose.ui.input.pointer.z r11, androidx.compose.foundation.text.u0 r12, androidx.compose.ui.input.pointer.f r13, kotlin.coroutines.jvm.internal.a r14) {
        /*
            Method dump skipped, instructions count: 224
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.W.k(androidx.compose.ui.input.pointer.z, androidx.compose.foundation.text.u0, androidx.compose.ui.input.pointer.f, kotlin.coroutines.jvm.internal.a):java.lang.Object");
    }

    public static final C0535p l(I i, C0534o c0534o, C0535p c0535p) {
        int i2 = i.b() ? c0534o.c : c0534o.d;
        if ((i.b() ? i.m() : i.h()) != c0534o.b) {
            return c0534o.a(i2);
        }
        kotlin.m mVar = kotlin.m.c;
        kotlin.k kVarA = kotlin.l.a(mVar, new androidx.compose.foundation.pager.H(c0534o, i2, i));
        kotlin.k kVarA2 = kotlin.l.a(mVar, new C0538t(c0534o, i2, i.b() ? c0534o.d : c0534o.c, i, kVarA));
        if (c0534o.a != c0535p.c) {
            return (C0535p) kVarA2.getValue();
        }
        int i3 = c0534o.e;
        if (i2 == i3) {
            return c0535p;
        }
        androidx.compose.ui.text.H h = c0534o.f;
        if (((Number) kVarA.getValue()).intValue() != h.f(i3)) {
            return (C0535p) kVarA2.getValue();
        }
        int i4 = c0535p.b;
        long jL = h.l(i4);
        boolean zB = i.b();
        if (i3 != -1) {
            if (i2 != i3) {
                if (((c0534o.b() != 1 ? 0 : 1) ^ (zB ? 1 : 0)) == 0) {
                }
            }
            return c0534o.a(i2);
        }
        int i5 = androidx.compose.ui.text.K.c;
        return (i4 == ((int) (jL >> 32)) || i4 == ((int) (jL & 4294967295L))) ? (C0535p) kVarA2.getValue() : c0534o.a(i2);
    }

    public static final C0535p m(C0534o c0534o, boolean z, boolean z2, int i, InterfaceC0528i interfaceC0528i) {
        long j;
        int i2 = z2 ? c0534o.c : c0534o.d;
        if (i != c0534o.b) {
            return c0534o.a(i2);
        }
        long jA = interfaceC0528i.a(c0534o, i2);
        if (z ^ z2) {
            int i3 = androidx.compose.ui.text.K.c;
            j = jA >> 32;
        } else {
            int i4 = androidx.compose.ui.text.K.c;
            j = 4294967295L & jA;
        }
        return c0534o.a((int) j);
    }

    public static final int n(int i, int i2, J j, long j2, C0535p c0535p) {
        if (c0535p == null) {
            return x(i, i2);
        }
        int iCompare = j.f.compare(Long.valueOf(c0535p.c), Long.valueOf(j2));
        if (iCompare < 0) {
            return 1;
        }
        return iCompare > 0 ? 3 : 2;
    }

    public static final C0535p o(C0535p c0535p, C0534o c0534o, int i) {
        return new C0535p(c0534o.f.a(i), i, c0535p.c);
    }

    public static final boolean p(androidx.compose.ui.geometry.c cVar, long j) {
        float fD = androidx.compose.ui.geometry.b.d(j);
        if (cVar.a > fD || fD > cVar.c) {
            return false;
        }
        float fE = androidx.compose.ui.geometry.b.e(j);
        return cVar.b <= fE && fE <= cVar.d;
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0029  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.compose.ui.graphics.C0848h q(androidx.compose.ui.draw.d r23, float r24) {
        /*
            r0 = r23
            r3 = r24
            double r1 = (double) r3
            double r1 = java.lang.Math.ceil(r1)
            float r1 = (float) r1
            int r1 = (int) r1
            int r1 = r1 * 2
            androidx.compose.ui.graphics.h r2 = androidx.compose.foundation.text.selection.W.b
            androidx.compose.ui.graphics.d r4 = androidx.compose.foundation.text.selection.W.c
            androidx.compose.ui.graphics.drawscope.b r5 = androidx.compose.foundation.text.selection.W.d
            if (r2 == 0) goto L29
            if (r4 == 0) goto L29
            android.graphics.Bitmap r6 = r2.a
            int r7 = r6.getWidth()
            if (r1 > r7) goto L29
            int r6 = r6.getHeight()
            if (r1 <= r6) goto L26
            goto L29
        L26:
            r8 = r2
            r9 = r4
            goto L37
        L29:
            r2 = 1
            androidx.compose.ui.graphics.h r2 = androidx.compose.ui.graphics.F.f(r1, r1, r2)
            androidx.compose.foundation.text.selection.W.b = r2
            androidx.compose.ui.graphics.d r4 = androidx.compose.ui.graphics.F.a(r2)
            androidx.compose.foundation.text.selection.W.c = r4
            goto L26
        L37:
            if (r5 != 0) goto L40
            androidx.compose.ui.graphics.drawscope.b r5 = new androidx.compose.ui.graphics.drawscope.b
            r5.<init>()
            androidx.compose.foundation.text.selection.W.d = r5
        L40:
            r10 = r5
            androidx.compose.ui.draw.b r1 = r0.a
            androidx.compose.ui.unit.k r1 = r1.getLayoutDirection()
            android.graphics.Bitmap r2 = r8.a
            int r4 = r2.getWidth()
            float r4 = (float) r4
            int r2 = r2.getHeight()
            float r2 = (float) r2
            long r4 = com.google.android.gms.internal.mlkit_vision_barcode.T4.a(r4, r2)
            androidx.compose.ui.graphics.drawscope.a r2 = r10.a
            androidx.compose.ui.unit.b r6 = r2.a
            androidx.compose.ui.unit.k r7 = r2.b
            androidx.compose.ui.graphics.s r11 = r2.c
            long r12 = r2.d
            r2.a = r0
            r2.b = r1
            r2.c = r9
            r2.d = r4
            r9.e()
            r0 = r11
            r4 = r12
            long r11 = androidx.compose.ui.graphics.C0861v.b
            long r15 = r10.g()
            r13 = 0
            r17 = 0
            r18 = 58
            androidx.compose.ui.graphics.drawscope.d.I(r10, r11, r13, r15, r17, r18)
            r19 = 4278190080(0xff000000, double:2.113706745E-314)
            long r11 = androidx.compose.ui.graphics.F.d(r19)
            long r15 = com.google.android.gms.internal.mlkit_vision_barcode.T4.a(r3, r3)
            r18 = 120(0x78, float:1.68E-43)
            androidx.compose.ui.graphics.drawscope.d.I(r10, r11, r13, r15, r17, r18)
            long r11 = androidx.compose.ui.graphics.F.d(r19)
            r13 = r4
            long r4 = com.google.android.gms.internal.mlkit_vision_barcode.Q4.c(r3, r3)
            r1 = r7
            r7 = 120(0x78, float:1.68E-43)
            r15 = r6
            r6 = 0
            r21 = r11
            r12 = r0
            r11 = r1
            r0 = r10
            r10 = r2
            r1 = r21
            androidx.compose.ui.graphics.drawscope.d.V(r0, r1, r3, r4, r6, r7)
            r9.q()
            r10.a = r15
            r10.b = r11
            r10.c = r12
            r10.d = r13
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.W.q(androidx.compose.ui.draw.d, float):androidx.compose.ui.graphics.h");
    }

    /* JADX WARN: Removed duplicated region for block: B:59:0x0107  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final long r(androidx.compose.foundation.text.selection.U r11, long r12, androidx.compose.foundation.text.selection.C0535p r14) {
        /*
            Method dump skipped, instructions count: 307
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.W.r(androidx.compose.foundation.text.selection.U, long, androidx.compose.foundation.text.selection.p):long");
    }

    public static final int s(long j, androidx.compose.ui.text.H h) {
        if (androidx.compose.ui.geometry.b.e(j) <= DefinitionKt.NO_Float_VALUE) {
            return 0;
        }
        float fE = androidx.compose.ui.geometry.b.e(j);
        androidx.compose.ui.text.o oVar = h.b;
        return fE >= oVar.e ? h.a.a.a.length() : oVar.e(j);
    }

    public static final long t(androidx.compose.ui.text.H h, int i, boolean z, boolean z2) {
        int iF = h.f(i);
        androidx.compose.ui.text.o oVar = h.b;
        if (iF >= oVar.f) {
            return 9205357640488583168L;
        }
        boolean z3 = h.a(((!z || z2) && (z || !z2)) ? Math.max(i + (-1), 0) : i) == h.j(i);
        oVar.j(i);
        int length = ((C0995g) oVar.a.b).a.length();
        ArrayList arrayList = oVar.h;
        androidx.compose.ui.text.q qVar = (androidx.compose.ui.text.q) arrayList.get(i == length ? kotlin.collections.B.i(arrayList) : AbstractC3169i5.b(i, arrayList));
        C0982b c0982b = qVar.a;
        int iB = qVar.b(i);
        androidx.compose.ui.text.android.x xVar = c0982b.d;
        float fH = z3 ? xVar.h(iB, false) : xVar.i(iB, false);
        long j = h.c;
        return Q4.c(kotlin.ranges.l.b(fH, DefinitionKt.NO_Float_VALUE, (int) (j >> 32)), kotlin.ranges.l.b(oVar.b(iF), DefinitionKt.NO_Float_VALUE, (int) (j & 4294967295L)));
    }

    public static final androidx.compose.ui.text.style.h u(androidx.compose.ui.text.H h, int i) {
        androidx.compose.ui.text.G g = h.a;
        if (g.a.a.length() != 0) {
            int iF = h.f(i);
            if ((i != 0 && iF == h.f(i - 1)) || (i != g.a.a.length() && iF == h.f(i + 1))) {
                return h.a(i);
            }
        }
        return h.j(i);
    }

    /* JADX WARN: Type inference failed for: r5v1, types: [java.lang.Object, java.util.List] */
    public static final boolean v(androidx.compose.ui.input.pointer.f fVar) {
        ?? r5 = fVar.a;
        int size = r5.size();
        for (int i = 0; i < size; i++) {
            if (((androidx.compose.ui.input.pointer.n) r5.get(i)).i != 2) {
                return false;
            }
        }
        return true;
    }

    public static final boolean w(i0 i0Var, boolean z) {
        androidx.compose.ui.layout.r rVarC;
        C0492h0 c0492h0 = i0Var.d;
        if (c0492h0 == null || (rVarC = c0492h0.c()) == null) {
            return false;
        }
        return p(y(rVarC), i0Var.k(z));
    }

    public static final int x(int i, int i2) {
        int iK = AbstractC0147y.k(i2);
        if (iK != 0) {
            if (iK != 1) {
                if (iK == 2) {
                    return 3;
                }
                throw new NoWhenBranchMatchedException();
            }
            int iK2 = AbstractC0147y.k(i);
            if (iK2 != 0) {
                if (iK2 == 1) {
                    return 2;
                }
                if (iK2 == 2) {
                    return 3;
                }
                throw new NoWhenBranchMatchedException();
            }
        }
        return 1;
    }

    public static final androidx.compose.ui.geometry.c y(androidx.compose.ui.layout.r rVar) {
        androidx.compose.ui.geometry.c cVarF = AbstractC0897s.f(rVar);
        long jE = rVar.E(Q4.c(cVarF.a, cVarF.b));
        long jE2 = rVar.E(Q4.c(cVarF.c, cVarF.d));
        return new androidx.compose.ui.geometry.c(androidx.compose.ui.geometry.b.d(jE), androidx.compose.ui.geometry.b.e(jE), androidx.compose.ui.geometry.b.d(jE2), androidx.compose.ui.geometry.b.e(jE2));
    }
}
