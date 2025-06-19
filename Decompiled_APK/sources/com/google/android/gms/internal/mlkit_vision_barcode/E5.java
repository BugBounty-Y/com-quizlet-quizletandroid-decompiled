package com.google.android.gms.internal.mlkit_vision_barcode;

import android.text.Spannable;
import android.text.style.AbsoluteSizeSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.E5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class E5 {
    /* JADX WARN: Removed duplicated region for block: B:48:0x0082  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0087  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0098  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x009a  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00a3  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00ed  */
    /* JADX WARN: Removed duplicated region for block: B:65:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(final kotlinx.collections.immutable.b r12, final int r13, final androidx.compose.ui.q r14, final kotlin.jvm.functions.Function1 r15, boolean r16, androidx.compose.runtime.InterfaceC0806l r17, final int r18, final int r19) {
        /*
            Method dump skipped, instructions count: 253
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.E5.a(kotlinx.collections.immutable.b, int, androidx.compose.ui.q, kotlin.jvm.functions.Function1, boolean, androidx.compose.runtime.l, int, int):void");
    }

    public static final void b(final androidx.compose.ui.q qVar, final String str, final long j, long j2, long j3, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        long j4;
        final long j5;
        final long j6;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-557580738);
        int i3 = i | (c0814p.f(str) ? 32 : 16) | (c0814p.e(j) ? 256 : 128) | 9216;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            j6 = j2;
            j5 = j3;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                androidx.compose.runtime.B b = com.quizlet.themes.g.a;
                ((com.quizlet.themes.b) c0814p.j(b)).c.getClass();
                long j7 = com.quizlet.ui.resources.designsystem.generated.d.T;
                long jH = ((com.quizlet.themes.b) c0814p.j(b)).H();
                i2 = i3 & (-64513);
                j4 = j7;
                j5 = jH;
            } else {
                c0814p.Q();
                i2 = i3 & (-64513);
                j4 = j2;
                j5 = j3;
            }
            c0814p.q();
            float f = com.quizlet.themes.m.H0;
            androidx.compose.foundation.shape.d dVar = androidx.compose.foundation.shape.e.a;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(androidx.compose.foundation.layout.K0.n(AbstractC0382e.u(AbstractC0460p.g(qVar, f, j, dVar), com.quizlet.themes.m.I0), com.quizlet.themes.m.F0, com.quizlet.themes.m.G0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 12), j4, dVar);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarF);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.material3.Q4.b(str, C0418x.a.a(androidx.compose.ui.n.b, androidx.compose.ui.b.e), j5, 0L, null, 0L, null, 0L, 0, false, 1, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).l, c0814p, (i2 >> 3) & 14, 3072, 57336);
            c0814p.p(true);
            j6 = j4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(str, j, j6, j5, i) { // from class: com.quizlet.ui.compose.e0
                public final /* synthetic */ String b;
                public final /* synthetic */ long c;
                public final /* synthetic */ long d;
                public final /* synthetic */ long e;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(7);
                    long j8 = this.d;
                    long j9 = this.e;
                    E5.b(this.a, this.b, this.c, j8, j9, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final float c(long j, float f, androidx.compose.ui.unit.b bVar) {
        float fC;
        long jB = androidx.compose.ui.unit.m.b(j);
        if (androidx.compose.ui.unit.n.a(jB, 4294967296L)) {
            if (bVar.Z() <= 1.05d) {
                return bVar.v0(j);
            }
            fC = androidx.compose.ui.unit.m.c(j) / androidx.compose.ui.unit.m.c(bVar.K(f));
        } else {
            if (!androidx.compose.ui.unit.n.a(jB, 8589934592L)) {
                return Float.NaN;
            }
            fC = androidx.compose.ui.unit.m.c(j);
        }
        return fC * f;
    }

    public static final void d(Spannable spannable, long j, int i, int i2) {
        if (j != 16) {
            spannable.setSpan(new ForegroundColorSpan(androidx.compose.ui.graphics.F.A(j)), i, i2, 33);
        }
    }

    public static final void e(Spannable spannable, long j, androidx.compose.ui.unit.b bVar, int i, int i2) {
        long jB = androidx.compose.ui.unit.m.b(j);
        if (androidx.compose.ui.unit.n.a(jB, 4294967296L)) {
            spannable.setSpan(new AbsoluteSizeSpan(kotlin.math.c.b(bVar.v0(j)), false), i, i2, 33);
        } else if (androidx.compose.ui.unit.n.a(jB, 8589934592L)) {
            spannable.setSpan(new RelativeSizeSpan(androidx.compose.ui.unit.m.c(j)), i, i2, 33);
        }
    }
}
