package androidx.compose.material3;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.material.C0559b;
import androidx.compose.material3.internal.AbstractC0646j;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0955m0;
import com.comscore.streaming.ContentType;
import com.quizlet.features.folders.composables.AbstractC4248d;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.f4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0618f4 {
    public static final float a = 125;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v0, types: [androidx.compose.runtime.internal.d, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r2v1, types: [androidx.compose.runtime.l, androidx.compose.runtime.p, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r4v11, types: [androidx.compose.runtime.internal.d] */
    public static final void a(C0624g4 c0624g4, androidx.compose.ui.q qVar, boolean z, boolean z2, boolean z3, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        boolean z4;
        boolean z5;
        androidx.compose.runtime.internal.d dVar2;
        ?? r0 = AbstractC4248d.a;
        ?? r2 = (C0814p) interfaceC0806l;
        r2.Z(-402577235);
        if ((i & 6) == 0) {
            i2 = (r2.f(c0624g4) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= r2.h(r0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= r2.f(qVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= r2.g(z) ? 2048 : 1024;
        }
        int i3 = i2 | 221184;
        if ((1572864 & i) == 0) {
            i3 |= r2.h(dVar) ? 1048576 : 524288;
        }
        if ((599187 & i3) == 599186 && r2.x()) {
            r2.Q();
            z4 = z2;
            z5 = z3;
            dVar2 = dVar;
        } else {
            boolean z6 = false;
            boolean z7 = true;
            boolean z8 = r2.j(AbstractC0955m0.l) == androidx.compose.ui.unit.k.b;
            androidx.work.impl.model.t tVar = c0624g4.b;
            EnumC0320d0 enumC0320d0 = EnumC0320d0.b;
            if (((EnumC0630h4) ((androidx.compose.runtime.L0) ((InterfaceC0773a0) tVar.g)).getValue()) == EnumC0630h4.c) {
                z6 = true;
            }
            androidx.compose.material.r rVar = (androidx.compose.material.r) tVar.f;
            if (((androidx.compose.runtime.L0) ((InterfaceC0773a0) tVar.l)).getValue() == null) {
                z7 = false;
            }
            androidx.compose.ui.q qVarA = androidx.compose.foundation.gestures.U.a(qVar, rVar, enumC0320d0, z6, z7, new C0559b(tVar, null, 1), 32);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, true);
            int i4 = r2.P;
            InterfaceC0803j0 interfaceC0803j0L = r2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(r2, qVarA);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            r2.b0();
            if (r2.O) {
                r2.k(c0913i);
            } else {
                r2.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(r2, kE, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(r2, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (r2.O || !Intrinsics.b(r2.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, r2, i4, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(r2, qVarC, c0912h4);
            C0418x c0418x = C0418x.a;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarB = c0418x.b(nVar);
            int i5 = (i3 << 6) & 7168;
            C0380d c0380d = AbstractC0398m.a;
            androidx.compose.ui.h hVar = androidx.compose.ui.b.j;
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(c0380d, hVar, r2, 0);
            int i6 = r2.P;
            InterfaceC0803j0 interfaceC0803j0L2 = r2.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(r2, qVarB);
            r2.b0();
            if (r2.O) {
                r2.k(c0913i);
            } else {
                r2.l0();
            }
            C0776c.E(r2, g0B, c0912h);
            C0776c.E(r2, interfaceC0803j0L2, c0912h2);
            if (r2.O || !Intrinsics.b(r2.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, r2, i6, c0912h3);
            }
            C0776c.E(r2, qVarC2, c0912h4);
            androidx.compose.foundation.layout.I0 i0 = androidx.compose.foundation.layout.I0.a;
            r0.invoke(i0, r2, Integer.valueOf(((i5 >> 6) & ContentType.LONG_FORM_ON_DEMAND) | 6));
            r2.p(true);
            boolean zG = r2.g(z8) | ((i3 & 7168) == 2048) | ((57344 & i3) == 16384) | ((i3 & 14) == 4);
            Object objI = r2.I();
            if (zG || objI == C0804k.a) {
                objI = new C0606d4(c0624g4, z, z8);
                r2.i0(objI);
            }
            androidx.compose.ui.q qVarD = AbstractC0646j.d(nVar, c0624g4.b, enumC0320d0, (Function2) objI);
            int i7 = (i3 >> 9) & 7168;
            androidx.compose.foundation.layout.G0 g0B2 = androidx.compose.foundation.layout.E0.b(c0380d, hVar, r2, 0);
            int i8 = r2.P;
            InterfaceC0803j0 interfaceC0803j0L3 = r2.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(r2, qVarD);
            r2.b0();
            if (r2.O) {
                r2.k(c0913i);
            } else {
                r2.l0();
            }
            C0776c.E(r2, g0B2, c0912h);
            C0776c.E(r2, interfaceC0803j0L3, c0912h2);
            if (r2.O || !Intrinsics.b(r2.I(), Integer.valueOf(i8))) {
                android.support.v4.media.session.a.z(i8, r2, i8, c0912h3);
            }
            C0776c.E(r2, qVarC3, c0912h4);
            Integer numValueOf = Integer.valueOf(((i7 >> 6) & ContentType.LONG_FORM_ON_DEMAND) | 6);
            ?? r4 = dVar;
            r4.invoke(i0, r2, numValueOf);
            z4 = true;
            r2.p(true);
            r2.p(true);
            z5 = true;
            dVar2 = r4;
        }
        C0813o0 c0813o0R = r2.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0612e4(c0624g4, qVar, z, z4, z5, dVar2, i);
        }
    }
}
