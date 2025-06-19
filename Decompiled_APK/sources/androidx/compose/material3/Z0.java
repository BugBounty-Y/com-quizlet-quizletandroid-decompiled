package androidx.compose.material3;

import androidx.compose.animation.C0281h;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.C0367i0;
import androidx.compose.foundation.C0555x;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.text.C0547v;
import androidx.compose.foundation.text.selection.C0527h;
import androidx.compose.material3.internal.AbstractC0646j;
import androidx.compose.material3.internal.AbstractC0655t;
import androidx.compose.material3.internal.C0654s;
import androidx.compose.material3.internal.C0656u;
import androidx.compose.material3.internal.C0657v;
import androidx.compose.material3.tokens.AbstractC0730d;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.semantics.ClearAndSetSemanticsElement;
import com.comscore.streaming.ContentType;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.Pair;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* loaded from: classes.dex */
public abstract class Z0 {
    public static final float a = 48;
    public static final float b = 56;
    public static final float c;
    public static final androidx.compose.foundation.layout.A0 d;
    public static final float e;

    static {
        float f = 12;
        c = f;
        d = AbstractC0382e.e(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, f, 3);
        float f2 = 24;
        float f3 = 16;
        AbstractC0382e.e(f2, f3, f, DefinitionKt.NO_Float_VALUE, 8);
        AbstractC0382e.e(f2, DefinitionKt.NO_Float_VALUE, f, f, 2);
        e = f3;
    }

    public static final void a(androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, C0699p0 c0699p0, androidx.compose.ui.text.L l, float f, androidx.compose.runtime.internal.d dVar4, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.runtime.internal.d dVar5;
        androidx.compose.runtime.internal.d dVar6;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1507356255);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(dVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            dVar5 = dVar2;
            i2 |= c0814p2.h(dVar5) ? 256 : 128;
        } else {
            dVar5 = dVar2;
        }
        if ((i & 3072) == 0) {
            dVar6 = dVar3;
            i2 |= c0814p2.h(dVar6) ? 2048 : 1024;
        } else {
            dVar6 = dVar3;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.f(c0699p0) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p2.f(l) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p2.c(f) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p2.h(dVar4) ? 8388608 : 4194304;
        }
        int i3 = i2;
        if ((i3 & 4793491) == 4793490 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.q qVarF = AbstractC0460p.f(androidx.compose.ui.semantics.m.a(androidx.compose.foundation.layout.K0.n(qVar, AbstractC0730d.a, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), false, C0736u.e), c0699p0.a, androidx.compose.ui.graphics.F.a);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p2, 0);
            int i4 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVarF);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, bA, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p2, i4, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            c(dVar, c0699p0.b, c0699p0.c, f, androidx.compose.runtime.internal.e.e(-229007058, new C0722t0(dVar5, dVar6, dVar, c0699p0, l, 0), c0814p2), c0814p2, (i3 & ContentType.LONG_FORM_ON_DEMAND) | 196614 | (57344 & (i3 >> 6)));
            c0814p = c0814p2;
            androidx.compose.animation.d0.w((i3 >> 21) & 14, dVar4, c0814p, true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.pager.w(qVar, dVar, dVar2, dVar3, c0699p0, l, f, dVar4, i);
        }
    }

    public static final void b(C0585a1 c0585a1, androidx.compose.ui.q qVar, C0716s0 c0716s0, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, boolean z, C0699p0 c0699p0, InterfaceC0806l interfaceC0806l, int i) {
        C0716s0 c0716s02;
        int i2;
        C0716s0 c0716s03;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(809701813);
        int i3 = i | (c0814p.f(c0585a1) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | 128 | (c0814p.f(c0699p0) ? 1048576 : 524288);
        if ((599187 & i3) == 599186 && c0814p.x()) {
            c0814p.Q();
            c0716s03 = c0716s0;
        } else {
            c0814p.S();
            int i4 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i4 == 0 || c0814p.w()) {
                Object objI = c0814p.I();
                if (objI == v) {
                    IntRange intRange = C0710r0.a;
                    objI = new C0716s0();
                    c0814p.i0(objI);
                }
                c0716s02 = (C0716s0) objI;
                i2 = i3 & (-897);
            } else {
                c0814p.Q();
                i2 = i3 & (-897);
                c0716s02 = c0716s0;
            }
            int i5 = i2;
            c0814p.q();
            Locale localeQ = Z1.q(c0814p);
            boolean zF = c0814p.f(localeQ);
            Object objI2 = c0814p.I();
            if (zF || objI2 == v) {
                objI2 = new C0656u(localeQ);
                c0814p.i0(objI2);
            }
            AbstractC0655t abstractC0655t = (AbstractC0655t) objI2;
            c0814p.X(255587712);
            androidx.compose.runtime.internal.d dVarE = z ? androidx.compose.runtime.internal.e.e(1982226759, new C0281h(c0585a1, 15), c0814p) : null;
            c0814p.p(false);
            C0716s0 c0716s04 = c0716s02;
            a(qVar, dVar, dVar2, dVarE, c0699p0, Z4.a(AbstractC0730d.g, c0814p), AbstractC0730d.f, androidx.compose.runtime.internal.e.e(-1840727866, new androidx.compose.animation.N(c0585a1, abstractC0655t, c0716s04, c0699p0, 2), c0814p), c0814p, ((i5 >> 3) & 14) | 14156208 | ((i5 >> 6) & 57344));
            c0716s03 = c0716s04;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0743v0(c0585a1, qVar, c0716s03, dVar, dVar2, z, c0699p0, i);
        }
    }

    public static final void c(androidx.compose.runtime.internal.d dVar, long j, long j2, float f, androidx.compose.runtime.internal.d dVar2, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-996037719);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(nVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(dVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.e(j) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.e(j2) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.c(f) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(dVar2) ? 131072 : 65536;
        }
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarG = androidx.compose.foundation.layout.K0.c(nVar, 1.0f).g(dVar != null ? androidx.compose.foundation.layout.K0.b(nVar, DefinitionKt.NO_Float_VALUE, f, 1) : nVar);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g, androidx.compose.ui.b.m, c0814p, 6);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(594325590);
            if (dVar != null) {
                AbstractC0646j.a(j, Z4.a(AbstractC0730d.h, c0814p), androidx.compose.runtime.internal.e.e(1936268514, new androidx.compose.foundation.layout.W(dVar, 12, (byte) 0), c0814p), c0814p, ((i2 >> 6) & 14) | 384);
            }
            c0814p.p(false);
            C0776c.a(androidx.compose.animation.d0.j(j2, AbstractC0669k0.a), dVar2, c0814p, ((i2 >> 12) & ContentType.LONG_FORM_ON_DEMAND) | 8);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new D0(dVar, j, j2, f, dVar2, i);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v1 */
    /* JADX WARN: Type inference failed for: r0v11 */
    /* JADX WARN: Type inference failed for: r0v2, types: [boolean, int] */
    public static final void d(boolean z, Function0 function0, boolean z2, boolean z3, boolean z4, String str, C0699p0 c0699p0, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        ?? r0;
        androidx.compose.runtime.W0 w0D;
        C0814p c0814p;
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1434777861);
        int i3 = i | (c0814p2.g(z) ? 32 : 16) | (c0814p2.h(function0) ? 256 : 128) | (c0814p2.g(z2) ? 2048 : 1024) | (c0814p2.g(z3) ? 16384 : 8192) | (c0814p2.g(z4) ? 131072 : 65536) | (c0814p2.g(false) ? 1048576 : 524288) | (c0814p2.f(str) ? 8388608 : 4194304) | (c0814p2.f(c0699p0) ? 67108864 : 33554432);
        if ((306783379 & i3) == 306783378 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            boolean z5 = (29360128 & i3) == 8388608;
            Object objI = c0814p2.I();
            if (z5 || objI == C0804k.a) {
                objI = new C0367i0(str, 4);
                c0814p2.i0(objI);
            }
            androidx.compose.ui.q qVarA = androidx.compose.ui.semantics.m.a(nVar, true, (Function1) objI);
            androidx.compose.ui.graphics.V vA = B3.a(c0814p2, AbstractC0730d.m);
            int i4 = i3 >> 3;
            long j = z ? z3 ? c0699p0.r : c0699p0.s : C0861v.f;
            if (z2) {
                c0814p2.X(-217363149);
                i2 = i4;
                r0 = 0;
                w0D = androidx.compose.animation.i0.a(j, AbstractC0240f.r(100, 0, null, 6), null, null, c0814p2, 0, 12);
                c0814p2.p(false);
            } else {
                i2 = i4;
                r0 = 0;
                c0814p2.X(-217247953);
                w0D = C0776c.D(new C0861v(j), c0814p2);
                c0814p2.p(false);
            }
            long j2 = ((C0861v) w0D.getValue()).a;
            long j3 = (z && z3) ? c0699p0.p : (!z || z3) ? z4 ? c0699p0.t : z3 ? c0699p0.n : c0699p0.o : c0699p0.q;
            c0814p2.X(-828241443);
            androidx.compose.runtime.W0 w0A = androidx.compose.animation.i0.a(j3, AbstractC0240f.r(100, r0, null, 6), null, null, c0814p2, 0, 12);
            c0814p2.p(r0);
            AbstractC0594b4.b(z, function0, qVarA, z3, vA, j2, ((C0861v) w0A.getValue()).a, (!z4 || z) ? null : AbstractC0460p.a(c0699p0.u, AbstractC0730d.e), null, androidx.compose.runtime.internal.e.e(-2031780827, new androidx.compose.foundation.layout.W(dVar, 13, (byte) 0), c0814p2), c0814p2, i2 & 7294, 1408);
            c0814p = c0814p2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new E0(z, function0, z2, z3, z4, str, c0699p0, dVar, i);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:39:0x00a1  */
    /* JADX WARN: Removed duplicated region for block: B:41:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void e(int r9, int r10, androidx.compose.runtime.InterfaceC0806l r11, androidx.compose.ui.q r12, kotlin.jvm.functions.Function1 r13) {
        /*
            r5 = r11
            androidx.compose.runtime.p r5 = (androidx.compose.runtime.C0814p) r5
            r11 = 1393846115(0x53146763, float:6.373897E11)
            r5.Z(r11)
            boolean r11 = r5.d(r9)
            if (r11 == 0) goto L12
            r11 = 32
            goto L14
        L12:
            r11 = 16
        L14:
            r11 = r11 | r10
            boolean r0 = r5.h(r13)
            r1 = 256(0x100, float:3.59E-43)
            if (r0 == 0) goto L1f
            r0 = r1
            goto L21
        L1f:
            r0 = 128(0x80, float:1.8E-43)
        L21:
            r11 = r11 | r0
            r0 = r11 & 147(0x93, float:2.06E-43)
            r2 = 146(0x92, float:2.05E-43)
            if (r0 != r2) goto L34
            boolean r0 = r5.x()
            if (r0 != 0) goto L2f
            goto L34
        L2f:
            r5.Q()
        L32:
            r1 = r12
            goto L9b
        L34:
            androidx.compose.runtime.V r0 = androidx.compose.runtime.C0804k.a
            r2 = 1
            r8 = 0
            if (r9 != 0) goto L6b
            r3 = -411219388(0xffffffffe77d4a44, float:-1.1961287E24)
            r5.X(r3)
            r11 = r11 & 896(0x380, float:1.256E-42)
            if (r11 != r1) goto L45
            goto L46
        L45:
            r2 = r8
        L46:
            java.lang.Object r11 = r5.I()
            if (r2 != 0) goto L4e
            if (r11 != r0) goto L57
        L4e:
            androidx.compose.material3.F0 r11 = new androidx.compose.material3.F0
            r0 = 0
            r11.<init>(r0, r13)
            r5.i0(r11)
        L57:
            r0 = r11
            kotlin.jvm.functions.Function0 r0 = (kotlin.jvm.functions.Function0) r0
            androidx.compose.runtime.internal.d r4 = androidx.compose.material3.AbstractC0620g0.a
            r2 = 0
            r3 = 0
            r6 = 196656(0x30030, float:2.75574E-40)
            r7 = 28
            r1 = r12
            androidx.compose.material3.Z1.h(r0, r1, r2, r3, r4, r5, r6, r7)
            r5.p(r8)
            goto L32
        L6b:
            r3 = -410937381(0xffffffffe78197db, float:-1.223973E24)
            r5.X(r3)
            r11 = r11 & 896(0x380, float:1.256E-42)
            if (r11 != r1) goto L76
            goto L77
        L76:
            r2 = r8
        L77:
            java.lang.Object r11 = r5.I()
            if (r2 != 0) goto L7f
            if (r11 != r0) goto L88
        L7f:
            androidx.compose.material3.F0 r11 = new androidx.compose.material3.F0
            r0 = 1
            r11.<init>(r0, r13)
            r5.i0(r11)
        L88:
            r0 = r11
            kotlin.jvm.functions.Function0 r0 = (kotlin.jvm.functions.Function0) r0
            androidx.compose.runtime.internal.d r4 = androidx.compose.material3.AbstractC0620g0.b
            r2 = 0
            r3 = 0
            r6 = 196656(0x30030, float:2.75574E-40)
            r7 = 28
            r1 = r12
            androidx.compose.material3.Z1.h(r0, r1, r2, r3, r4, r5, r6, r7)
            r5.p(r8)
        L9b:
            androidx.compose.runtime.o0 r11 = r5.r()
            if (r11 == 0) goto La8
            androidx.compose.foundation.y r12 = new androidx.compose.foundation.y
            r12.<init>(r9, r10, r1, r13)
            r11.d = r12
        La8:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.Z0.e(int, int, androidx.compose.runtime.l, androidx.compose.ui.q, kotlin.jvm.functions.Function1):void");
    }

    public static final void f(androidx.compose.foundation.lazy.A a2, Long l, Function1 function1, Function1 function12, AbstractC0655t abstractC0655t, IntRange intRange, C0716s0 c0716s0, InterfaceC0764y3 interfaceC0764y3, C0699p0 c0699p0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Long l2;
        Object j0;
        androidx.compose.foundation.lazy.A a3 = a2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1994757941);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(a3) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            l2 = l;
            i2 |= c0814p.f(l2) ? 32 : 16;
        } else {
            l2 = l;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function1) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function12) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(abstractC0655t) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(intRange) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= (2097152 & i) == 0 ? c0814p.f(c0716s0) : c0814p.h(c0716s0) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p.f(interfaceC0764y3) ? 8388608 : 4194304;
        }
        if ((100663296 & i) == 0) {
            i2 |= c0814p.f(c0699p0) ? 67108864 : 33554432;
        }
        if ((38347923 & i2) == 38347922 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0654s c0654sB = abstractC0655t.b();
            boolean zF = c0814p.f(intRange);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (zF || objI == v) {
                objI = ((C0656u) abstractC0655t).d(LocalDate.of(intRange.a, 1, 1));
                c0814p.i0(objI);
            }
            int i3 = i2;
            Q4.a(Z4.a(AbstractC0730d.b, c0814p), androidx.compose.runtime.internal.e.e(1504086906, new I0(a3, intRange, abstractC0655t, (C0657v) objI, function1, c0654sB, l2, c0716s0, interfaceC0764y3, c0699p0), c0814p), c0814p, 48);
            boolean zH = ((i3 & 14) == 4) | ((i3 & 7168) == 2048) | c0814p.h(abstractC0655t) | c0814p.h(intRange);
            Object objI2 = c0814p.I();
            if (zH || objI2 == v) {
                a3 = a2;
                j0 = new J0(a3, function12, abstractC0655t, intRange, null);
                c0814p.i0(j0);
            } else {
                j0 = objI2;
                a3 = a2;
            }
            C0776c.f(c0814p, a3, (Function2) j0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new K0(a3, l, function1, function12, abstractC0655t, intRange, c0716s0, interfaceC0764y3, c0699p0, i);
        }
    }

    public static final void g(C0657v c0657v, Function1 function1, long j, Long l, C0716s0 c0716s0, InterfaceC0764y3 interfaceC0764y3, C0699p0 c0699p0, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        int i2;
        int i3;
        androidx.compose.ui.n nVar;
        float f;
        Locale locale;
        C0814p c0814p2;
        androidx.compose.ui.n nVar2;
        boolean z;
        boolean z2;
        float f2;
        Function1 function12 = function1;
        Long l2 = l;
        C0716s0 c0716s02 = c0716s0;
        C0814p c0814p3 = (C0814p) interfaceC0806l;
        c0814p3.Z(-1912870997);
        C0699p0 c0699p02 = c0699p0;
        int i4 = i | (c0814p3.f(c0657v) ? 4 : 2) | (c0814p3.h(function12) ? 32 : 16) | (c0814p3.e(j) ? 256 : 128) | (c0814p3.f(l2) ? 2048 : 1024) | (c0814p3.f(c0716s02) ? 1048576 : 524288) | (c0814p3.f(interfaceC0764y3) ? 8388608 : 4194304) | (c0814p3.f(c0699p02) ? 67108864 : 33554432);
        if ((i4 & 38347923) == 38347922 && c0814p3.x()) {
            c0814p3.Q();
            c0814p = c0814p3;
        } else {
            c0814p3.X(1821433443);
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            c0814p3.p(false);
            Locale localeQ = Z1.q(c0814p3);
            float f3 = a;
            androidx.compose.ui.q qVarG = androidx.compose.foundation.layout.K0.g(nVar3, 6 * f3).g(nVar3);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.f, androidx.compose.ui.b.m, c0814p3, 6);
            int i5 = c0814p3.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p3.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p3, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p3.b0();
            if (c0814p3.O) {
                c0814p3.k(c0913i);
            } else {
                c0814p3.l0();
            }
            C0776c.E(c0814p3, bA, C0914j.f);
            C0776c.E(c0814p3, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p3.O || !Intrinsics.b(c0814p3.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p3, i5, c0912h);
            }
            C0776c.E(c0814p3, qVarC, C0914j.d);
            c0814p3.X(-647461340);
            int i6 = 0;
            int i7 = 0;
            while (i7 < 6) {
                androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
                androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.f, androidx.compose.ui.b.k, c0814p3, 54);
                int i8 = c0814p3.P;
                InterfaceC0803j0 interfaceC0803j0L2 = c0814p3.l();
                androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p3, qVarC2);
                InterfaceC0915k.D0.getClass();
                int i9 = i6;
                C0913i c0913i2 = C0914j.b;
                c0814p3.b0();
                int i10 = i7;
                if (c0814p3.O) {
                    c0814p3.k(c0913i2);
                } else {
                    c0814p3.l0();
                }
                C0776c.E(c0814p3, g0B, C0914j.f);
                C0776c.E(c0814p3, interfaceC0803j0L2, C0914j.e);
                C0912h c0912h2 = C0914j.g;
                if (c0814p3.O || !Intrinsics.b(c0814p3.I(), Integer.valueOf(i8))) {
                    android.support.v4.media.session.a.z(i8, c0814p3, i8, c0912h2);
                }
                C0776c.E(c0814p3, qVarC3, C0914j.d);
                c0814p3.X(-88395975);
                int i11 = i9;
                int i12 = 0;
                while (i12 < 7) {
                    int i13 = c0657v.d;
                    if (i11 < i13 || i11 >= i13 + c0657v.c) {
                        i2 = i11;
                        i3 = i12;
                        nVar = nVar3;
                        f = f3;
                        locale = localeQ;
                        c0814p2 = c0814p3;
                        c0814p2.X(1554856342);
                        AbstractC0382e.f(c0814p2, androidx.compose.foundation.layout.K0.i(nVar, f, f));
                        c0814p2.p(false);
                    } else {
                        c0814p3.X(1555370911);
                        int i14 = i11 - c0657v.d;
                        i2 = i11;
                        i3 = i12;
                        long j2 = (i14 * 86400000) + c0657v.e;
                        boolean z3 = j2 == j;
                        if (l2 != null && j2 == l2.longValue()) {
                            nVar2 = nVar3;
                            z = true;
                        } else {
                            nVar2 = nVar3;
                            z = false;
                        }
                        c0814p3.X(-88360892);
                        c0814p3.p(false);
                        StringBuilder sb = new StringBuilder();
                        c0814p3.X(-647730741);
                        c0814p3.p(false);
                        c0814p3.X(-647717033);
                        if (z3) {
                            if (sb.length() > 0) {
                                sb.append(", ");
                            }
                            z2 = z;
                            sb.append(AbstractC0646j.g(c0814p3, R.string.m3c_date_picker_today_description));
                        } else {
                            z2 = z;
                        }
                        c0814p3.p(false);
                        String string = sb.length() == 0 ? null : sb.toString();
                        boolean z4 = z3;
                        String strA = c0716s02.a(Long.valueOf(j2), localeQ, true);
                        if (strA == null) {
                            strA = "";
                        }
                        boolean zE = ((i4 & ContentType.LONG_FORM_ON_DEMAND) == 32) | c0814p3.e(j2);
                        Object objI = c0814p3.I();
                        androidx.compose.runtime.V v = C0804k.a;
                        if (zE || objI == v) {
                            f2 = f3;
                            objI = new L0(function12, j2, 0);
                            c0814p3.i0(objI);
                        } else {
                            f2 = f3;
                        }
                        Function0 function0 = (Function0) objI;
                        boolean zE2 = ((i4 & 29360128) == 8388608) | c0814p3.e(j2);
                        Object objI2 = c0814p3.I();
                        if (zE2 || objI2 == v) {
                            objI2 = Boolean.valueOf(interfaceC0764y3.b(c0657v.a) && interfaceC0764y3.a(j2));
                            c0814p3.i0(objI2);
                        }
                        boolean zBooleanValue = ((Boolean) objI2).booleanValue();
                        if (string != null) {
                            strA = android.support.v4.media.session.a.l(string, ", ", strA);
                        }
                        C0814p c0814p4 = c0814p3;
                        locale = localeQ;
                        nVar = nVar2;
                        f = f2;
                        d(z2, function0, z2, zBooleanValue, z4, strA, c0699p02, androidx.compose.runtime.internal.e.e(-2095706591, new C0547v(i14, 1), c0814p3), c0814p4, (i4 & 234881024) | 805306374);
                        c0814p2 = c0814p4;
                        c0814p2.p(false);
                    }
                    l2 = l;
                    c0716s02 = c0716s0;
                    c0699p02 = c0699p0;
                    localeQ = locale;
                    f3 = f;
                    c0814p3 = c0814p2;
                    i11 = i2 + 1;
                    i12 = i3 + 1;
                    nVar3 = nVar;
                    function12 = function1;
                }
                androidx.compose.ui.n nVar4 = nVar3;
                C0814p c0814p5 = c0814p3;
                c0814p5.p(false);
                c0814p5.p(true);
                l2 = l;
                c0716s02 = c0716s0;
                c0699p02 = c0699p0;
                localeQ = localeQ;
                f3 = f3;
                i6 = i11;
                i7 = i10 + 1;
                c0814p3 = c0814p5;
                nVar3 = nVar4;
                function12 = function1;
            }
            c0814p = c0814p3;
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new M0(c0657v, function1, j, l, c0716s0, interfaceC0764y3, c0699p0, i);
        }
    }

    public static final void h(androidx.compose.ui.q qVar, boolean z, boolean z2, boolean z3, String str, Function0 function0, Function0 function02, Function0 function03, C0699p0 c0699p0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function0 function04;
        Function0 function05;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-773929258);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.g(z) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.g(z2) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.g(z3) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.f(str) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(function0) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            function04 = function02;
            i2 |= c0814p.h(function04) ? 1048576 : 524288;
        } else {
            function04 = function02;
        }
        if ((12582912 & i) == 0) {
            function05 = function03;
            i2 |= c0814p.h(function05) ? 8388608 : 4194304;
        } else {
            function05 = function03;
        }
        if ((100663296 & i) == 0) {
            i2 |= c0814p.f(c0699p0) ? 67108864 : 33554432;
        }
        if ((i2 & 38347923) == 38347922 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarG = androidx.compose.foundation.layout.K0.g(androidx.compose.foundation.layout.K0.c(qVar, 1.0f), b);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(z3 ? AbstractC0398m.a : AbstractC0398m.g, androidx.compose.ui.b.k, c0814p, 48);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            C0776c.a(AbstractC0669k0.a.a(new C0861v(c0699p0.f)), androidx.compose.runtime.internal.e.e(-962805198, new N0(function05, z3, str, function04, z2, function0, z), c0814p), c0814p, 56);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new O0(qVar, z, z2, z3, str, function0, function02, function03, c0699p0, i);
        }
    }

    public static final void i(C0699p0 c0699p0, AbstractC0655t abstractC0655t, InterfaceC0806l interfaceC0806l, int i) {
        boolean z = true;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1849465391);
        int i2 = (i & 6) == 0 ? (c0814p.f(c0699p0) ? 4 : 2) | i : i;
        if ((i & 48) == 0) {
            i2 |= c0814p.h(abstractC0655t) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0656u c0656u = (C0656u) abstractC0655t;
            int i3 = c0656u.b;
            ArrayList arrayList = c0656u.c;
            ArrayList arrayList2 = new ArrayList();
            int i4 = i3 - 1;
            int size = arrayList.size();
            for (int i5 = i4; i5 < size; i5++) {
                arrayList2.add(arrayList.get(i5));
            }
            boolean z2 = false;
            for (int i6 = 0; i6 < i4; i6++) {
                arrayList2.add(arrayList.get(i6));
            }
            androidx.compose.ui.text.L lA = Z4.a(AbstractC0730d.i, c0814p);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            float f = a;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(androidx.compose.foundation.layout.K0.b(nVar, DefinitionKt.NO_Float_VALUE, f, 1), 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.f, androidx.compose.ui.b.k, c0814p, 54);
            int i7 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i7))) {
                android.support.v4.media.session.a.z(i7, c0814p, i7, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            c0814p.X(396197267);
            int size2 = arrayList2.size();
            int i8 = 0;
            while (i8 < size2) {
                Pair pair = (Pair) arrayList2.get(i8);
                boolean zF = c0814p.f(pair);
                Object objI = c0814p.I();
                if (zF || objI == C0804k.a) {
                    objI = new androidx.camera.lifecycle.f(pair, 27);
                    c0814p.i0(objI);
                }
                AtomicInteger atomicInteger = androidx.compose.ui.semantics.m.a;
                androidx.compose.ui.q qVarL = androidx.compose.foundation.layout.K0.l(new ClearAndSetSemanticsElement((Function1) objI), f, f);
                androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.e, z2);
                int i9 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
                androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarL);
                InterfaceC0915k.D0.getClass();
                C0913i c0913i2 = C0914j.b;
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i2);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, kE, C0914j.f);
                C0776c.E(c0814p, interfaceC0803j0L2, C0914j.e);
                C0912h c0912h2 = C0914j.g;
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i9))) {
                    android.support.v4.media.session.a.z(i9, c0814p, i9, c0912h2);
                }
                C0776c.E(c0814p, qVarC3, C0914j.d);
                C0814p c0814p2 = c0814p;
                Q4.b((String) pair.b, androidx.compose.foundation.layout.K0.s(nVar, null, 3), c0699p0.d, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, lA, c0814p2, 48, 0, 65016);
                c0814p = c0814p2;
                c0814p.p(true);
                i8++;
                z2 = false;
                z = true;
                f = f;
                nVar = nVar;
                size2 = size2;
                arrayList2 = arrayList2;
            }
            c0814p.p(z2);
            c0814p.p(z);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.animation.core.D0(c0699p0, abstractC0655t, i, 8);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x01cf  */
    /* JADX WARN: Removed duplicated region for block: B:105:0x01e3  */
    /* JADX WARN: Removed duplicated region for block: B:109:0x0200  */
    /* JADX WARN: Removed duplicated region for block: B:113:0x0217  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x0268  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x026e  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x028a  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x02ad  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x02b1  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x02cc  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void j(java.lang.Long r27, long r28, kotlin.jvm.functions.Function1 r30, kotlin.jvm.functions.Function1 r31, androidx.compose.material3.internal.AbstractC0655t r32, kotlin.ranges.IntRange r33, androidx.compose.material3.C0716s0 r34, androidx.compose.material3.InterfaceC0764y3 r35, androidx.compose.material3.C0699p0 r36, androidx.compose.runtime.InterfaceC0806l r37, int r38) {
        /*
            Method dump skipped, instructions count: 915
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.Z0.j(java.lang.Long, long, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, androidx.compose.material3.internal.t, kotlin.ranges.IntRange, androidx.compose.material3.s0, androidx.compose.material3.y3, androidx.compose.material3.p0, androidx.compose.runtime.l, int):void");
    }

    public static final void k(Long l, long j, int i, Function1 function1, Function1 function12, AbstractC0655t abstractC0655t, IntRange intRange, C0716s0 c0716s0, InterfaceC0764y3 interfaceC0764y3, C0699p0 c0699p0, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-895379221);
        if ((i2 & 6) == 0) {
            i3 = (c0814p2.f(l) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p2.e(j) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p2.d(i) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p2.h(function1) ? 2048 : 1024;
        }
        if ((i2 & 24576) == 0) {
            i3 |= c0814p2.h(function12) ? 16384 : 8192;
        }
        if ((196608 & i2) == 0) {
            i3 |= c0814p2.h(abstractC0655t) ? 131072 : 65536;
        }
        if ((1572864 & i2) == 0) {
            i3 |= c0814p2.h(intRange) ? 1048576 : 524288;
        }
        if ((12582912 & i2) == 0) {
            i3 |= (16777216 & i2) == 0 ? c0814p2.f(c0716s0) : c0814p2.h(c0716s0) ? 8388608 : 4194304;
        }
        if ((100663296 & i2) == 0) {
            i3 |= c0814p2.f(interfaceC0764y3) ? 67108864 : 33554432;
        }
        if ((805306368 & i2) == 0) {
            i3 |= c0814p2.f(c0699p0) ? 536870912 : 268435456;
        }
        if ((306783379 & i3) == 306783378 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            int i4 = -((androidx.compose.ui.unit.b) c0814p2.j(AbstractC0955m0.f)).m0(48);
            C0615f1 c0615f1 = new C0615f1(i);
            int i5 = i3;
            androidx.compose.ui.q qVarA = androidx.compose.ui.semantics.m.a(androidx.compose.ui.n.b, false, C0736u.h);
            boolean zD = c0814p2.d(i4);
            Object objI = c0814p2.I();
            if (zD || objI == C0804k.a) {
                objI = new androidx.compose.foundation.lazy.grid.w(i4, 3);
                c0814p2.i0(objI);
            }
            c0814p = c0814p2;
            androidx.compose.animation.E.b(c0615f1, qVarA, (Function1) objI, null, "DatePickerDisplayModeAnimation", null, androidx.compose.runtime.internal.e.e(-459778869, new P0(l, j, function1, function12, abstractC0655t, intRange, c0716s0, interfaceC0764y3, c0699p0), c0814p2), c0814p, ((i5 >> 6) & 14) | 1597440, 40);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Q0(l, j, i, function1, function12, abstractC0655t, intRange, c0716s0, interfaceC0764y3, c0699p0, i2);
        }
    }

    public static final void l(androidx.compose.ui.q qVar, boolean z, boolean z2, Function0 function0, boolean z3, String str, C0699p0 c0699p0, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Object objA;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(238547184);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.g(z) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.g(z2) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function0) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.g(z3) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.f(str) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p.f(c0699p0) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p.h(dVar) ? 8388608 : 4194304;
        }
        if ((4793491 & i2) == 4793490 && c0814p.x()) {
            c0814p.Q();
        } else {
            boolean z4 = ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i2 & 896) == 256);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z4 || objI == v) {
                objA = (!z2 || z) ? null : AbstractC0460p.a(c0699p0.u, AbstractC0730d.e);
                c0814p.i0(objA);
            } else {
                objA = objI;
            }
            C0555x c0555x = (C0555x) objA;
            boolean z5 = (458752 & i2) == 131072;
            Object objI2 = c0814p.I();
            if (z5 || objI2 == v) {
                objI2 = new C0367i0(str, 6);
                c0814p.i0(objI2);
            }
            int i3 = i2 >> 3;
            AbstractC0594b4.b(z, function0, androidx.compose.ui.semantics.m.a(qVar, true, (Function1) objI2), z3, B3.a(c0814p, AbstractC0730d.A), ((C0861v) androidx.compose.animation.i0.a(z ? z3 ? c0699p0.l : c0699p0.m : C0861v.f, AbstractC0240f.r(100, 0, null, 6), null, null, c0814p, 0, 12).getValue()).a, ((C0861v) androidx.compose.animation.i0.a((z && z3) ? c0699p0.j : (!z || z3) ? z2 ? c0699p0.i : z3 ? c0699p0.g : c0699p0.h : c0699p0.k, AbstractC0240f.r(100, 0, null, 6), null, null, c0814p, 0, 12).getValue()).a, c0555x, null, androidx.compose.runtime.internal.e.e(-1573188346, new androidx.compose.foundation.layout.W(dVar, 14, (byte) 0), c0814p), c0814p, (i3 & 14) | ((i2 >> 6) & ContentType.LONG_FORM_ON_DEMAND) | (i3 & 7168), 1408);
            c0814p = c0814p;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new R0(qVar, z, z2, function0, z3, str, c0699p0, dVar, i);
        }
    }

    public static final void m(androidx.compose.ui.q qVar, long j, Function1 function1, InterfaceC0764y3 interfaceC0764y3, AbstractC0655t abstractC0655t, IntRange intRange, C0699p0 c0699p0, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1286899812);
        if ((i & 6) == 0) {
            qVar2 = qVar;
            i2 = (c0814p.f(qVar2) ? 4 : 2) | i;
        } else {
            qVar2 = qVar;
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.e(j) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function1) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(interfaceC0764y3) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(abstractC0655t) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(intRange) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p.f(c0699p0) ? 1048576 : 524288;
        }
        if ((i2 & 599187) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            Q4.a(Z4.a(AbstractC0730d.l, c0814p), androidx.compose.runtime.internal.e.e(1301915789, new M0(abstractC0655t, j, intRange, c0699p0, qVar2, function1, interfaceC0764y3), c0814p), c0814p, 48);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new V0(qVar, j, function1, interfaceC0764y3, abstractC0655t, intRange, c0699p0, i);
        }
    }

    public static final void n(Function0 function0, boolean z, androidx.compose.ui.n nVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(409654418);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.g(z) ? 32 : 16;
        }
        int i3 = i2 | 384;
        if ((i & 3072) == 0) {
            i3 |= c0814p.h(dVar) ? 2048 : 1024;
        }
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.foundation.shape.d dVar2 = androidx.compose.foundation.shape.e.a;
            androidx.compose.foundation.layout.A0 a0 = L.a;
            long j = ((C0861v) c0814p.j(AbstractC0669k0.a)).a;
            long j2 = C0861v.g;
            Z1.m(function0, nVar3, false, dVar2, L.c((Z) c0814p.j(AbstractC0590b0.a)).a(j2, j, j2, j2), null, androidx.compose.runtime.internal.e.e(1899012021, new C0527h(z, 1, dVar), c0814p), c0814p, (i3 & 14) | 807075840 | ((i3 >> 3) & ContentType.LONG_FORM_ON_DEMAND), 388);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.contextmenu.p(function0, z, nVar2, dVar, i);
        }
    }
}
