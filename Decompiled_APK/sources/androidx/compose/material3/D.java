package androidx.compose.material3;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0274x;
import androidx.compose.foundation.C0473q;
import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.InterfaceC0388h;
import androidx.compose.foundation.layout.InterfaceC0394k;
import androidx.compose.material3.internal.AbstractC0646j;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.semantics.ClearAndSetSemanticsElement;
import com.comscore.streaming.ContentType;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class D {
    public static final float a;
    public static final float b;
    public static final C0274x c = new C0274x(0.8f, DefinitionKt.NO_Float_VALUE, 0.8f, 0.15f);
    public static final float d = 24;
    public static final float e = 28;
    public static final float f;
    public static final float g;

    static {
        float f2 = 16;
        float f3 = f2 - 12;
        a = f3;
        b = f3;
        float f4 = 4;
        f = f4;
        g = f2 - f4;
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x003f  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x004f  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0054  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x006d  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0082  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0098  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00b8  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x00d8  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x00da  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x00dd  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x00e0  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x00e3  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x00ea  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x010f  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x0148  */
    /* JADX WARN: Removed duplicated region for block: B:96:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(androidx.compose.runtime.internal.d r20, androidx.compose.ui.q r21, androidx.compose.runtime.internal.d r22, androidx.compose.runtime.internal.d r23, float r24, androidx.compose.foundation.layout.R0 r25, androidx.compose.material3.V4 r26, androidx.compose.runtime.InterfaceC0806l r27, int r28, int r29) {
        /*
            Method dump skipped, instructions count: 344
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.D.a(androidx.compose.runtime.internal.d, androidx.compose.ui.q, androidx.compose.runtime.internal.d, androidx.compose.runtime.internal.d, float, androidx.compose.foundation.layout.R0, androidx.compose.material3.V4, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:100:0x012b  */
    /* JADX WARN: Removed duplicated region for block: B:102:0x012e  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x0139  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x0165  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x0179  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x01ba  */
    /* JADX WARN: Removed duplicated region for block: B:123:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x003f  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0044  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x005c  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x007b  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0090  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00ae  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00b2  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x00cc  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x00e4  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x010b  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x010d  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0110  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x0113  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x011c  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x011f  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0125  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(androidx.compose.runtime.internal.d r28, androidx.compose.ui.n r29, androidx.compose.runtime.internal.d r30, androidx.compose.runtime.internal.d r31, float r32, float r33, androidx.compose.foundation.layout.R0 r34, androidx.compose.material3.V4 r35, com.quizlet.data.repository.achievements.h r36, androidx.compose.runtime.InterfaceC0806l r37, int r38, int r39) {
        /*
            Method dump skipped, instructions count: 454
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.D.b(androidx.compose.runtime.internal.d, androidx.compose.ui.n, androidx.compose.runtime.internal.d, androidx.compose.runtime.internal.d, float, float, androidx.compose.foundation.layout.R0, androidx.compose.material3.V4, com.quizlet.data.repository.achievements.h, androidx.compose.runtime.l, int, int):void");
    }

    public static final void c(androidx.compose.runtime.internal.d dVar, androidx.compose.ui.n nVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, float f2, float f3, androidx.compose.foundation.layout.R0 r0, V4 v4, com.quizlet.data.repository.achievements.h hVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        float f4;
        float f5;
        androidx.compose.ui.n nVar2;
        androidx.compose.runtime.internal.d dVar4;
        C0814p c0814p;
        androidx.compose.ui.n nVar3;
        androidx.compose.runtime.internal.d dVar5;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1879191686);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(dVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        int i3 = i2 | 48;
        if ((i & 384) == 0) {
            i3 |= c0814p2.h(dVar2) ? 256 : 128;
        }
        int i4 = i3 | 224256;
        if ((1572864 & i) == 0) {
            i4 |= c0814p2.f(r0) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i4 |= c0814p2.f(v4) ? 8388608 : 4194304;
        }
        if ((100663296 & i) == 0) {
            i4 |= c0814p2.f(hVar) ? 67108864 : 33554432;
        }
        if ((38347923 & i4) == 38347922 && c0814p2.x()) {
            c0814p2.Q();
            nVar3 = nVar;
            dVar5 = dVar3;
            f4 = f2;
            f5 = f3;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                androidx.compose.ui.n nVar4 = androidx.compose.ui.n.b;
                androidx.compose.runtime.internal.d dVar6 = AbstractC0614f0.b;
                f4 = W4.b;
                f5 = W4.c;
                nVar2 = nVar4;
                dVar4 = dVar6;
            } else {
                c0814p2.Q();
                nVar2 = nVar;
                dVar4 = dVar3;
                f4 = f2;
                f5 = f3;
            }
            c0814p2.q();
            androidx.compose.ui.text.L lA = Z4.a(androidx.compose.material3.tokens.C.b, c0814p2);
            androidx.compose.ui.text.L lA2 = Z4.a(androidx.compose.material3.tokens.D.c, c0814p2);
            float f6 = (androidx.compose.ui.unit.e.a(f4, Float.NaN) || androidx.compose.ui.unit.e.a(f4, Float.POSITIVE_INFINITY)) ? W4.b : f4;
            float f7 = (androidx.compose.ui.unit.e.a(f5, Float.NaN) || androidx.compose.ui.unit.e.a(f5, Float.POSITIVE_INFINITY)) ? W4.c : f5;
            int i5 = i4 << 12;
            c0814p = c0814p2;
            f(nVar2, dVar, lA, d, dVar, lA2, dVar2, dVar4, f6, f7, r0, v4, hVar, c0814p, ((i4 >> 3) & 14) | 3072 | ((i4 << 3) & ContentType.LONG_FORM_ON_DEMAND) | (57344 & i5) | (3670016 & i5) | (i5 & 29360128), (i4 >> 18) & 1022);
            nVar3 = nVar2;
            dVar5 = dVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0698p(dVar, nVar3, dVar2, dVar5, f4, f5, r0, v4, hVar, i);
        }
    }

    public static final void d(androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, androidx.compose.ui.text.L l, boolean z, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, float f2, androidx.compose.foundation.layout.R0 r0, V4 v4, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        boolean z2;
        androidx.compose.runtime.internal.d dVar4;
        boolean z3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-342194911);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(dVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(l) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            z2 = z;
            i2 |= c0814p.g(z2) ? 2048 : 1024;
        } else {
            z2 = z;
        }
        if ((i & 24576) == 0) {
            dVar4 = dVar2;
            i2 |= c0814p.h(dVar4) ? 16384 : 8192;
        } else {
            dVar4 = dVar2;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(dVar3) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p.c(f2) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p.f(r0) ? 8388608 : 4194304;
        }
        if ((100663296 & i) == 0) {
            i2 |= c0814p.f(v4) ? 67108864 : 33554432;
        }
        if ((805306368 & i) == 0) {
            i2 |= c0814p.f(null) ? 536870912 : 268435456;
        }
        if ((306783379 & i2) == 306783378 && c0814p.x()) {
            c0814p.Q();
        } else {
            if (Float.isNaN(f2) || f2 == Float.POSITIVE_INFINITY) {
                throw new IllegalArgumentException("The expandedHeight is expected to be specified and finite");
            }
            float fC0 = ((androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f)).c0(f2);
            if (fC0 < DefinitionKt.NO_Float_VALUE) {
                fC0 = 0.0f;
            }
            int i3 = i2 & 1879048192;
            boolean zC = (i3 == 536870912) | c0814p.c(fC0);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (zC || objI == v) {
                objI = new C0584a0(fC0);
                c0814p.i0(objI);
            }
            C0776c.i((Function0) objI, c0814p);
            boolean z4 = i3 == 536870912;
            Object objI2 = c0814p.I();
            if (z4 || objI2 == v) {
                z3 = false;
                objI2 = C0776c.q(new C0584a0(0, 20));
                c0814p.i0(objI2);
            } else {
                z3 = false;
            }
            float fFloatValue = ((Number) ((androidx.compose.runtime.W0) objI2).getValue()).floatValue();
            v4.getClass();
            androidx.compose.runtime.W0 w0A = androidx.compose.animation.i0.a(androidx.compose.ui.graphics.F.r(v4.a, v4.b, androidx.compose.animation.core.C.c.b(fFloatValue)), AbstractC0240f.q(5, null), null, null, c0814p, 48, 12);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(1370231018, new androidx.compose.foundation.layout.W(dVar3, 7, (byte) 0), c0814p);
            c0814p.X(-1193605157);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            c0814p.p(z3);
            AbstractC0594b4.a(qVar.g(nVar), null, ((C0861v) w0A.getValue()).a, 0L, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, null, androidx.compose.runtime.internal.e.e(-1943739546, new r(r0, f2, v4, dVar, l, z2, dVar4, dVarE), c0814p), c0814p, 12582912, ContentType.USER_GENERATED_LONG_FORM_ON_DEMAND);
            c0814p = c0814p;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0715s(qVar, dVar, l, z, dVar2, dVar3, f2, r0, v4, i);
        }
    }

    public static final void e(androidx.compose.runtime.internal.d dVar, androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, float f2, androidx.compose.foundation.layout.R0 r0, V4 v4, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        float f3;
        C0814p c0814p;
        float f4;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(226148675);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(dVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(dVar2) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.h(dVar3) ? 2048 : 1024;
        }
        int i3 = i2 | 24576;
        if ((196608 & i) == 0) {
            i3 |= c0814p2.f(r0) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i3 |= c0814p2.f(v4) ? 1048576 : 524288;
        }
        int i4 = i3 | 12582912;
        if ((4793491 & i4) == 4793490 && c0814p2.x()) {
            c0814p2.Q();
            f4 = f2;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                f3 = W4.a;
            } else {
                c0814p2.Q();
                f3 = f2;
            }
            c0814p2.q();
            androidx.compose.ui.text.L lA = Z4.a(androidx.compose.material3.tokens.D.c, c0814p2);
            float f5 = (androidx.compose.ui.unit.e.a(f3, Float.NaN) || androidx.compose.ui.unit.e.a(f3, Float.POSITIVE_INFINITY)) ? W4.a : f3;
            int i5 = ((i4 >> 3) & 14) | 3072 | ((i4 << 3) & ContentType.LONG_FORM_ON_DEMAND);
            int i6 = i4 << 6;
            c0814p = c0814p2;
            d(qVar, dVar, lA, false, dVar2, dVar3, f5, r0, v4, c0814p, i5 | (57344 & i6) | (458752 & i6) | (29360128 & i6) | (234881024 & i6) | (i6 & 1879048192));
            f4 = f3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0721t(dVar, qVar, dVar2, dVar3, f4, r0, v4, i);
        }
    }

    public static final void f(androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, androidx.compose.ui.text.L l, float f2, androidx.compose.runtime.internal.d dVar2, androidx.compose.ui.text.L l2, androidx.compose.runtime.internal.d dVar3, androidx.compose.runtime.internal.d dVar4, float f3, float f4, androidx.compose.foundation.layout.R0 r0, V4 v4, com.quizlet.data.repository.achievements.h hVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        boolean z;
        int i4;
        int i5;
        C0814p c0814p;
        X4 x4;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1169193376);
        if ((i & 6) == 0) {
            i3 = (c0814p2.f(qVar) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            z = true;
            i3 |= c0814p2.h(dVar) ? 32 : 16;
        } else {
            z = true;
        }
        if ((i & 384) == 0) {
            i3 |= c0814p2.f(l) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i3 |= c0814p2.c(f2) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p2.h(dVar2) ? 16384 : 8192;
        }
        if ((i & 196608) == 0) {
            i4 = 6;
            i3 |= c0814p2.f(l2) ? 131072 : 65536;
        } else {
            i4 = 6;
        }
        if ((i & 1572864) == 0) {
            i3 |= c0814p2.h(dVar3) ? 1048576 : 524288;
        }
        if ((i & 12582912) == 0) {
            i3 |= c0814p2.h(dVar4) ? 8388608 : 4194304;
        }
        if ((i & 100663296) == 0) {
            i3 |= c0814p2.c(f3) ? 67108864 : 33554432;
        }
        if ((i & 805306368) == 0) {
            i3 |= c0814p2.c(f4) ? 536870912 : 268435456;
        }
        if ((i2 & 6) == 0) {
            i5 = i2 | (c0814p2.f(r0) ? 4 : 2);
        } else {
            i5 = i2;
        }
        if ((i2 & 48) == 0) {
            i5 |= c0814p2.f(v4) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i5 |= c0814p2.f(hVar) ? 256 : 128;
        }
        int i6 = i5;
        if ((i3 & 306783379) == 306783378 && (i6 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            if (Float.isNaN(f3) || f3 == Float.POSITIVE_INFINITY) {
                throw new IllegalArgumentException("The collapsedHeight is expected to be specified and finite");
            }
            if (Float.isNaN(f4) || f4 == Float.POSITIVE_INFINITY) {
                throw new IllegalArgumentException("The expandedHeight is expected to be specified and finite");
            }
            if (Float.compare(f4, f3) < 0) {
                throw new IllegalArgumentException("The expandedHeight is expected to be greater or equal to the collapsedHeight");
            }
            kotlin.jvm.internal.G g2 = new kotlin.jvm.internal.G();
            kotlin.jvm.internal.G g3 = new kotlin.jvm.internal.G();
            kotlin.jvm.internal.H h = new kotlin.jvm.internal.H();
            androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p2.j(AbstractC0955m0.f);
            g2.a = bVar.c0(f4);
            g3.a = bVar.c0(f3);
            h.a = bVar.m0(f2);
            Unit unit = Unit.a;
            int i7 = i6 & 896;
            boolean zC = (i7 == 256 ? z : false) | c0814p2.c(g3.a) | c0814p2.c(g2.a);
            Object objI = c0814p2.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (zC || objI == v) {
                objI = new C0473q(hVar, g3, g2, i4);
                c0814p2.i0(objI);
            }
            C0776c.i((Function0) objI, c0814p2);
            float fA = (hVar == null || (x4 = (X4) hVar.a) == null) ? DefinitionKt.NO_Float_VALUE : x4.a();
            v4.getClass();
            long jR = androidx.compose.ui.graphics.F.r(v4.a, v4.b, androidx.compose.animation.core.C.c.b(fA));
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(-89435287, new androidx.compose.foundation.layout.W(dVar4, 8, (byte) 0), c0814p2);
            float fB = c.b(fA);
            float f5 = 1.0f - fA;
            boolean z2 = fA < 0.5f ? z : false;
            boolean z3 = !z2;
            c0814p2.X(1641266888);
            androidx.compose.ui.q qVarA = androidx.compose.ui.n.b;
            if (hVar != null) {
                EnumC0320d0 enumC0320d0 = EnumC0320d0.a;
                boolean z4 = i7 == 256 ? z : false;
                Object objI2 = c0814p2.I();
                if (z4 || objI2 == v) {
                    objI2 = new androidx.camera.lifecycle.f(hVar, 25);
                    c0814p2.i0(objI2);
                }
                androidx.compose.foundation.gestures.Z zB = androidx.compose.foundation.gestures.U.b((Function1) objI2, c0814p2);
                if (i7 != 256) {
                    z = false;
                }
                Object objI3 = c0814p2.I();
                if (z || objI3 == v) {
                    objI3 = new B(hVar, null);
                    c0814p2.i0(objI3);
                }
                qVarA = androidx.compose.foundation.gestures.U.a(qVarA, zB, enumC0320d0, false, false, (kotlin.jvm.functions.c) objI3, 188);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0594b4.a(qVar.g(qVarA), null, jR, 0L, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, null, androidx.compose.runtime.internal.e.e(-1350062619, new C0766z(r0, f3, v4, dVar2, l2, fB, z2, dVar3, dVarE, f4, hVar, dVar, l, f5, h, z3), c0814p2), c0814p, 12582912, ContentType.USER_GENERATED_LONG_FORM_ON_DEMAND);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new A(qVar, dVar, l, f2, dVar2, l2, dVar3, dVar4, f3, f4, r0, v4, hVar, i, i2);
        }
    }

    public static final void g(androidx.compose.ui.q qVar, InterfaceC0758x3 interfaceC0758x3, long j, long j2, long j3, androidx.compose.runtime.internal.d dVar, androidx.compose.ui.text.L l, float f2, InterfaceC0394k interfaceC0394k, InterfaceC0388h interfaceC0388h, int i, boolean z, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, InterfaceC0806l interfaceC0806l, int i2, int i3) {
        int i4;
        int i5;
        androidx.compose.ui.q clearAndSetSemanticsElement;
        C0814p c0814p;
        long j4 = j3;
        androidx.compose.runtime.internal.d dVar4 = dVar3;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-742442296);
        if ((i2 & 6) == 0) {
            i4 = i2 | (c0814p2.f(qVar) ? 4 : 2);
        } else {
            i4 = i2;
        }
        if ((i2 & 48) == 0) {
            i4 |= (i2 & 64) == 0 ? c0814p2.f(interfaceC0758x3) : c0814p2.h(interfaceC0758x3) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i4 |= c0814p2.e(j) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i4 |= c0814p2.e(j2) ? 2048 : 1024;
        }
        if ((i2 & 24576) == 0) {
            i4 |= c0814p2.e(j4) ? 16384 : 8192;
        }
        if ((196608 & i2) == 0) {
            i4 |= c0814p2.h(dVar) ? 131072 : 65536;
        }
        if ((i2 & 1572864) == 0) {
            i4 |= c0814p2.f(l) ? 1048576 : 524288;
        }
        if ((12582912 & i2) == 0) {
            i4 |= c0814p2.c(f2) ? 8388608 : 4194304;
        }
        if ((i2 & 100663296) == 0) {
            i4 |= c0814p2.f(interfaceC0394k) ? 67108864 : 33554432;
        }
        if ((i2 & 805306368) == 0) {
            i4 |= c0814p2.f(interfaceC0388h) ? 536870912 : 268435456;
        }
        if ((i3 & 6) == 0) {
            i5 = i3 | (c0814p2.d(i) ? 4 : 2);
        } else {
            i5 = i3;
        }
        if ((i3 & 48) == 0) {
            i5 |= c0814p2.g(z) ? 32 : 16;
        }
        if ((i3 & 384) == 0) {
            i5 |= c0814p2.h(dVar2) ? 256 : 128;
        }
        if ((i3 & 3072) == 0) {
            i5 |= c0814p2.h(dVar4) ? 2048 : 1024;
        }
        int i6 = i5;
        if ((i4 & 306783379) == 306783378 && (i6 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            boolean z2 = ((i4 & 1879048192) == 536870912) | ((i4 & ContentType.LONG_FORM_ON_DEMAND) == 32 || ((i4 & 64) != 0 && c0814p2.h(interfaceC0758x3))) | ((i4 & 234881024) == 67108864) | ((i6 & 14) == 4);
            Object objI = c0814p2.I();
            if (z2 || objI == C0804k.a) {
                objI = new C0748w(interfaceC0758x3, interfaceC0388h, interfaceC0394k, i);
                c0814p2.i0(objI);
            }
            androidx.compose.ui.layout.K k = (androidx.compose.ui.layout.K) objI;
            int i7 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p2, k, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p2, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i7))) {
                android.support.v4.media.session.a.z(i7, c0814p2, i7, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p2, qVarC, c0912h4);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarK = AbstractC0897s.k(nVar, "navigationIcon");
            float f3 = f;
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarK, f3, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14);
            androidx.compose.ui.i iVar = androidx.compose.ui.b.a;
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(iVar, false);
            int i8 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p2.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p2, qVarY);
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, kE, c0912h);
            C0776c.E(c0814p2, interfaceC0803j0L2, c0912h2);
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i8))) {
                android.support.v4.media.session.a.z(i8, c0814p2, i8, c0912h3);
            }
            C0776c.E(c0814p2, qVarC2, c0912h4);
            androidx.compose.runtime.B b2 = AbstractC0669k0.a;
            C0776c.a(androidx.compose.animation.d0.j(j, b2), dVar2, c0814p2, ((i6 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | 8);
            c0814p2.p(true);
            androidx.compose.ui.q qVarW = AbstractC0382e.w(AbstractC0897s.k(nVar, "title"), f3, DefinitionKt.NO_Float_VALUE, 2);
            if (z) {
                C0736u c0736u = C0736u.b;
                AtomicInteger atomicInteger = androidx.compose.ui.semantics.m.a;
                clearAndSetSemanticsElement = new ClearAndSetSemanticsElement(c0736u);
            } else {
                clearAndSetSemanticsElement = nVar;
            }
            androidx.compose.ui.q qVarQ = androidx.compose.ui.graphics.F.q(qVarW.g(clearAndSetSemanticsElement), DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, null, false, 131067);
            androidx.compose.ui.layout.K kE2 = AbstractC0409s.e(iVar, false);
            int i9 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L3 = c0814p2.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p2, qVarQ);
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, kE2, c0912h);
            C0776c.E(c0814p2, interfaceC0803j0L3, c0912h2);
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i9))) {
                android.support.v4.media.session.a.z(i9, c0814p2, i9, c0912h3);
            }
            C0776c.E(c0814p2, qVarC3, c0912h4);
            int i10 = i4 >> 9;
            AbstractC0646j.a(j2, l, dVar, c0814p2, (i10 & 14) | ((i4 >> 15) & ContentType.LONG_FORM_ON_DEMAND) | (i10 & 896));
            c0814p = c0814p2;
            c0814p.p(true);
            androidx.compose.ui.q qVarY2 = AbstractC0382e.y(AbstractC0897s.k(nVar, "actionIcons"), DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f3, DefinitionKt.NO_Float_VALUE, 11);
            androidx.compose.ui.layout.K kE3 = AbstractC0409s.e(iVar, false);
            int i11 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L4 = c0814p.l();
            androidx.compose.ui.q qVarC4 = androidx.compose.ui.a.c(c0814p, qVarY2);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE3, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L4, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i11))) {
                android.support.v4.media.session.a.z(i11, c0814p, i11, c0912h3);
            }
            C0776c.E(c0814p, qVarC4, c0912h4);
            j4 = j3;
            dVar4 = dVar3;
            C0776c.a(b2.a(new C0861v(j4)), dVar4, c0814p, 8 | ((i6 >> 6) & ContentType.LONG_FORM_ON_DEMAND));
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0754x(qVar, interfaceC0758x3, j, j2, j4, dVar, l, f2, interfaceC0394k, interfaceC0388h, i, z, dVar2, dVar4, i2, i3);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object h(androidx.compose.material3.X4 r9, float r10, androidx.compose.animation.core.C0276z r11, androidx.compose.animation.core.InterfaceC0256n r12, kotlin.coroutines.jvm.internal.c r13) {
        /*
            Method dump skipped, instructions count: 252
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.D.h(androidx.compose.material3.X4, float, androidx.compose.animation.core.z, androidx.compose.animation.core.n, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final X4 i(InterfaceC0806l interfaceC0806l) {
        Object[] objArr = new Object[0];
        com.quizlet.data.repository.explanations.myexplanations.a aVar = X4.d;
        boolean zC = ((C0814p) interfaceC0806l).c(-3.4028235E38f) | ((C0814p) interfaceC0806l).c(DefinitionKt.NO_Float_VALUE) | ((C0814p) interfaceC0806l).c(DefinitionKt.NO_Float_VALUE);
        C0814p c0814p = (C0814p) interfaceC0806l;
        Object objI = c0814p.I();
        if (zC || objI == C0804k.a) {
            objI = new C0584a0(0, 21);
            c0814p.i0(objI);
        }
        return (X4) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, aVar, (Function0) objI, c0814p, 0, 4);
    }
}
