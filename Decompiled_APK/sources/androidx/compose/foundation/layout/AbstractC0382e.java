package androidx.compose.foundation.layout;

import androidx.compose.runtime.AbstractC0772a;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.layout.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0382e {
    public static final C0380d a = new C0380d(0);
    public static final C0380d b = new C0380d(1);
    public static final int c = 9;
    public static final int d = 6;
    public static final int e = 10;
    public static final int f = 5;
    public static final int g = 15;

    public static final C0408r0 A(androidx.core.graphics.e eVar) {
        return new C0408r0(eVar.a, eVar.b, eVar.c, eVar.d);
    }

    public static final void B(String str, StringBuilder sb) {
        if (sb.length() > 0) {
            sb.append('+');
        }
        sb.append(str);
    }

    public static final androidx.compose.ui.q C(androidx.compose.ui.q qVar, int i) {
        return qVar.g(new IntrinsicWidthElement(i));
    }

    public static final void a(androidx.compose.ui.q qVar, androidx.compose.ui.i iVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        androidx.compose.ui.i iVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1781813501);
        if ((i & 6) == 0) {
            i3 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        int i4 = i2 & 2;
        if (i4 != 0) {
            i3 |= 48;
        } else if ((i & 48) == 0) {
            i3 |= c0814p.f(iVar) ? 32 : 16;
        }
        int i5 = i3 | 384;
        if ((i & 3072) == 0) {
            i5 |= c0814p.h(dVar) ? 2048 : 1024;
        }
        if ((i5 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            iVar2 = iVar;
        } else {
            androidx.compose.ui.i iVar3 = i4 != 0 ? androidx.compose.ui.b.a : iVar;
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(iVar3, false);
            boolean zF = ((i5 & 7168) == 2048) | c0814p.f(kE);
            Object objI = c0814p.I();
            if (zF || objI == C0804k.a) {
                objI = new androidx.compose.foundation.contextmenu.i(5, kE, dVar);
                c0814p.i0(objI);
            }
            AbstractC0897s.c(qVar, (Function2) objI, c0814p, i5 & 14, 0);
            iVar2 = iVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0419y(qVar, iVar2, dVar, i, i2);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:106:0x017f A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:107:0x0181  */
    /* JADX WARN: Removed duplicated region for block: B:113:0x01bd  */
    /* JADX WARN: Removed duplicated region for block: B:115:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0045  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0055  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x006b  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0096  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0098  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00a9  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00b7  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00c6  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00c9  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00d2  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x011e  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x0124  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x013a  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0144  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0158  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(int r21, androidx.compose.ui.q r22, androidx.compose.foundation.layout.InterfaceC0388h r23, androidx.compose.foundation.layout.InterfaceC0394k r24, int r25, int r26, androidx.compose.foundation.layout.I r27, androidx.compose.runtime.internal.d r28, androidx.compose.runtime.InterfaceC0806l r29, int r30, int r31) {
        /*
            Method dump skipped, instructions count: 463
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.layout.AbstractC0382e.b(int, androidx.compose.ui.q, androidx.compose.foundation.layout.h, androidx.compose.foundation.layout.k, int, int, androidx.compose.foundation.layout.I, androidx.compose.runtime.internal.d, androidx.compose.runtime.l, int, int):void");
    }

    public static A0 c(float f2, float f3, int i) {
        if ((i & 1) != 0) {
            f2 = 0;
        }
        if ((i & 2) != 0) {
            f3 = 0;
        }
        return new A0(f2, f3, f2, f3);
    }

    public static final A0 d(float f2, float f3, float f4, float f5) {
        return new A0(f2, f3, f4, f5);
    }

    public static A0 e(float f2, float f3, float f4, float f5, int i) {
        if ((i & 1) != 0) {
            f2 = 0;
        }
        if ((i & 2) != 0) {
            f3 = 0;
        }
        if ((i & 4) != 0) {
            f4 = 0;
        }
        if ((i & 8) != 0) {
            f5 = 0;
        }
        return new A0(f2, f3, f4, f5);
    }

    public static final void f(InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar) {
        r rVar = r.c;
        C0814p c0814p = (C0814p) interfaceC0806l;
        int i = c0814p.P;
        androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(interfaceC0806l, qVar);
        InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
        InterfaceC0915k.D0.getClass();
        C0913i c0913i = C0914j.b;
        AbstractC0772a abstractC0772a = c0814p.a;
        c0814p.b0();
        if (c0814p.O) {
            c0814p.k(c0913i);
        } else {
            c0814p.l0();
        }
        C0776c.E(interfaceC0806l, rVar, C0914j.f);
        C0776c.E(interfaceC0806l, interfaceC0803j0L, C0914j.e);
        C0776c.E(interfaceC0806l, qVarC, C0914j.d);
        C0912h c0912h = C0914j.g;
        if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i))) {
            android.support.v4.media.session.a.z(i, c0814p, i, c0912h);
        }
        c0814p.p(true);
    }

    public static androidx.compose.ui.q h(androidx.compose.ui.q qVar) {
        return qVar.g(new AspectRatioElement());
    }

    public static final float j(z0 z0Var, androidx.compose.ui.unit.k kVar) {
        return kVar == androidx.compose.ui.unit.k.a ? z0Var.c(kVar) : z0Var.b(kVar);
    }

    public static final float k(z0 z0Var, androidx.compose.ui.unit.k kVar) {
        return kVar == androidx.compose.ui.unit.k.a ? z0Var.b(kVar) : z0Var.c(kVar);
    }

    public static long l(int i, long j) {
        return L5.a(i == 1 ? androidx.compose.ui.unit.a.j(j) : androidx.compose.ui.unit.a.i(j), i == 1 ? androidx.compose.ui.unit.a.h(j) : androidx.compose.ui.unit.a.g(j), i == 1 ? androidx.compose.ui.unit.a.i(j) : androidx.compose.ui.unit.a.j(j), i == 1 ? androidx.compose.ui.unit.a.g(j) : androidx.compose.ui.unit.a.h(j));
    }

    public static long m(int i, long j) {
        return L5.a(0, androidx.compose.ui.unit.a.h(j), (i & 4) != 0 ? androidx.compose.ui.unit.a.i(j) : 0, androidx.compose.ui.unit.a.g(j));
    }

    public static final D0 n(androidx.compose.ui.layout.J j) {
        Object objG = j.G();
        if (objG instanceof D0) {
            return (D0) objG;
        }
        return null;
    }

    public static final float o(D0 d0) {
        return d0 != null ? d0.a : DefinitionKt.NO_Float_VALUE;
    }

    public static final androidx.compose.ui.q p(androidx.compose.ui.q qVar, int i) {
        return qVar.g(new IntrinsicHeightElement(i));
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x004c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.compose.ui.layout.L q(androidx.compose.foundation.layout.C0 r43, int r44, int r45, int r46, int r47, int r48, androidx.compose.ui.layout.M r49, java.util.List r50, androidx.compose.ui.layout.W[] r51, int r52, int r53, int[] r54, int r55) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 879
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.layout.AbstractC0382e.q(androidx.compose.foundation.layout.C0, int, int, int, int, int, androidx.compose.ui.layout.M, java.util.List, androidx.compose.ui.layout.W[], int, int, int[], int):androidx.compose.ui.layout.L");
    }

    public static final androidx.compose.ui.q r(androidx.compose.ui.q qVar, Function1 function1) {
        return qVar.g(new OffsetPxElement(function1, new androidx.compose.animation.U(2, function1)));
    }

    public static androidx.compose.ui.q s(androidx.compose.ui.q qVar, float f2, float f3, int i) {
        if ((i & 1) != 0) {
            f2 = 0;
        }
        if ((i & 2) != 0) {
            f3 = 0;
        }
        return qVar.g(new OffsetElement(f2, f3, new C0406q(1, 7)));
    }

    public static final androidx.compose.ui.q t(androidx.compose.ui.q qVar, z0 z0Var) {
        return qVar.g(new PaddingValuesElement(z0Var, new C0406q(1, 11)));
    }

    public static final androidx.compose.ui.q u(androidx.compose.ui.q qVar, float f2) {
        return qVar.g(new PaddingElement(f2, f2, f2, f2, new C0406q(1, 10)));
    }

    public static final androidx.compose.ui.q v(androidx.compose.ui.q qVar, float f2, float f3) {
        return qVar.g(new PaddingElement(f2, f3, f2, f3, new C0406q(1, 9)));
    }

    public static androidx.compose.ui.q w(androidx.compose.ui.q qVar, float f2, float f3, int i) {
        if ((i & 1) != 0) {
            f2 = 0;
        }
        if ((i & 2) != 0) {
            f3 = 0;
        }
        return v(qVar, f2, f3);
    }

    public static final androidx.compose.ui.q x(androidx.compose.ui.q qVar, float f2, float f3, float f4, float f5) {
        return qVar.g(new PaddingElement(f2, f3, f4, f5, new C0406q(1, 8)));
    }

    public static androidx.compose.ui.q y(androidx.compose.ui.q qVar, float f2, float f3, float f4, float f5, int i) {
        if ((i & 1) != 0) {
            f2 = 0;
        }
        if ((i & 2) != 0) {
            f3 = 0;
        }
        if ((i & 4) != 0) {
            f4 = 0;
        }
        if ((i & 8) != 0) {
            f5 = 0;
        }
        return x(qVar, f2, f3, f4, f5);
    }

    public static final long z(int i, long j) {
        return i == 1 ? L5.a(androidx.compose.ui.unit.a.j(j), androidx.compose.ui.unit.a.h(j), androidx.compose.ui.unit.a.i(j), androidx.compose.ui.unit.a.g(j)) : L5.a(androidx.compose.ui.unit.a.i(j), androidx.compose.ui.unit.a.g(j), androidx.compose.ui.unit.a.j(j), androidx.compose.ui.unit.a.h(j));
    }

    public abstract int g(int i, androidx.compose.ui.unit.k kVar, androidx.compose.ui.layout.W w, int i2);

    public Integer i(androidx.compose.ui.layout.W w) {
        return null;
    }
}
