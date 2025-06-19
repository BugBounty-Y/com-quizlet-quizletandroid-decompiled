package androidx.compose.material3;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0811n0;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class T3 {
    public static final float d;
    public static final float f;
    public static final float a = com.pubmatic.sdk.video.a.GENERAL_COMPANION_AD_ERROR;
    public static final float b = 30;
    public static final float c = 16;
    public static final float e = 6;

    static {
        float f2 = 8;
        d = f2;
        f = f2;
    }

    /* JADX WARN: Removed duplicated region for block: B:111:0x0149  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x014b  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x014f  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x0155  */
    /* JADX WARN: Removed duplicated region for block: B:119:0x0161  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x0168  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x0176  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x01c7  */
    /* JADX WARN: Removed duplicated region for block: B:130:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0057  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x005a  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x007e  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0085  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0094  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x009b  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x00aa  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00c5  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x00cd  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x00e6  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x00ef  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x00fe  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x011c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(androidx.compose.ui.q r32, androidx.compose.runtime.internal.d r33, androidx.compose.runtime.internal.d r34, androidx.compose.ui.graphics.V r35, long r36, long r38, long r40, long r42, androidx.compose.runtime.internal.d r44, androidx.compose.runtime.InterfaceC0806l r45, int r46, int r47) {
        /*
            Method dump skipped, instructions count: 480
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.T3.a(androidx.compose.ui.q, androidx.compose.runtime.internal.d, androidx.compose.runtime.internal.d, androidx.compose.ui.graphics.V, long, long, long, long, androidx.compose.runtime.internal.d, androidx.compose.runtime.l, int, int):void");
    }

    public static final void b(androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.ui.text.L l, long j, long j2, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.runtime.internal.d dVar4;
        androidx.compose.ui.text.L l2;
        int i3;
        androidx.compose.runtime.internal.d dVar5;
        long j3;
        boolean z;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-903235475);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(dVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(dVar2) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(dVar3) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(l) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.e(j) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.e(j2) ? 131072 : 65536;
        }
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
            dVar4 = dVar2;
            dVar5 = dVar3;
            l2 = l;
            j3 = j2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, c, DefinitionKt.NO_Float_VALUE, dVar3 == null ? d : 0, DefinitionKt.NO_Float_VALUE, 10);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = new C0601d(1);
                c0814p.i0(objI);
            }
            androidx.compose.ui.layout.K k = (androidx.compose.ui.layout.K) objI;
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarY);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            int i5 = i2;
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, k, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            androidx.compose.ui.q qVarW = AbstractC0382e.w(AbstractC0897s.k(nVar, "text"), DefinitionKt.NO_Float_VALUE, e, 1);
            androidx.compose.ui.i iVar = androidx.compose.ui.b.a;
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(iVar, false);
            int i6 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarW);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            dVar.invoke(c0814p, Integer.valueOf(i5 & 14));
            c0814p.p(true);
            c0814p.X(-904778058);
            if (dVar2 != null) {
                androidx.compose.ui.q qVarK = AbstractC0897s.k(nVar, "action");
                androidx.compose.ui.layout.K kE2 = AbstractC0409s.e(iVar, false);
                int i7 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
                androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarK);
                c0814p.b0();
                i3 = 8;
                if (c0814p.O) {
                    c0814p.k(c0913i);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, kE2, c0912h);
                C0776c.E(c0814p, interfaceC0803j0L3, c0912h2);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i7))) {
                    android.support.v4.media.session.a.z(i7, c0814p, i7, c0912h3);
                }
                C0776c.E(c0814p, qVarC3, c0912h4);
                l2 = l;
                dVar4 = dVar2;
                C0776c.b(new C0811n0[]{androidx.compose.animation.d0.j(j, AbstractC0669k0.a), Q4.a.a(l2)}, dVar4, c0814p, 8 | (i5 & ContentType.LONG_FORM_ON_DEMAND));
                c0814p.p(true);
            } else {
                dVar4 = dVar2;
                l2 = l;
                i3 = 8;
            }
            c0814p.p(false);
            c0814p.X(-904766579);
            if (dVar3 != null) {
                androidx.compose.ui.q qVarK2 = AbstractC0897s.k(nVar, "dismissAction");
                androidx.compose.ui.layout.K kE3 = AbstractC0409s.e(iVar, false);
                int i8 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L4 = c0814p.l();
                androidx.compose.ui.q qVarC4 = androidx.compose.ui.a.c(c0814p, qVarK2);
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, kE3, c0912h);
                C0776c.E(c0814p, interfaceC0803j0L4, c0912h2);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                    android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h3);
                }
                C0776c.E(c0814p, qVarC4, c0912h4);
                j3 = j2;
                dVar5 = dVar3;
                C0776c.a(androidx.compose.animation.d0.j(j3, AbstractC0669k0.a), dVar5, c0814p, i3 | ((i5 >> 3) & ContentType.LONG_FORM_ON_DEMAND));
                z = true;
                c0814p.p(true);
            } else {
                dVar5 = dVar3;
                j3 = j2;
                z = true;
            }
            c0814p.p(false);
            c0814p.p(z);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0756x1(dVar, dVar4, dVar5, l2, j, j3, i);
        }
    }
}
