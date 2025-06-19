package com.quizlet.explanations.solution.recyclerview.step;

import android.content.Context;
import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import androidx.compose.foundation.layout.A;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.E0;
import androidx.compose.foundation.layout.G0;
import androidx.compose.foundation.layout.K0;
import androidx.compose.material3.Q4;
import androidx.compose.material3.V;
import androidx.compose.material3.Z1;
import androidx.compose.runtime.B;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.X0;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.C0854n;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.compose.ui.platform.N;
import androidx.compose.ui.q;
import androidx.compose.ui.text.L;
import androidx.navigation.U;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3187k5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3673m4;
import com.quizlet.data.model.SimpleImage;
import com.quizlet.quizletandroid.R;
import com.quizlet.themes.m;
import com.quizlet.themes.w;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class i {
    public static final float a = 7;

    public static final void a(com.quizlet.qutils.string.f fVar, com.quizlet.qutils.string.f fVar2, q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1206179517);
        if (((i | (c0814p2.h(fVar) ? 4 : 2) | (c0814p2.h(fVar2) ? 32 : 16)) & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            G0 g0B = E0.b(AbstractC0398m.g, androidx.compose.ui.b.k, c0814p2, 54);
            int i2 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            q qVarC = androidx.compose.ui.a.c(c0814p2, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, g0B, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p2, i2, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            X0 x0 = AndroidCompositionLocals_androidKt.b;
            String strE = AbstractC3053s1.e(fVar, (Context) c0814p2.j(x0));
            B b = w.b;
            L l = ((com.quizlet.themes.f) c0814p2.j(b)).g;
            B b2 = com.quizlet.themes.g.a;
            Q4.b(strE, null, ((com.quizlet.themes.b) c0814p2.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p2, 0, 0, 65530);
            Q4.b(AbstractC3053s1.e(fVar2, (Context) c0814p2.j(x0)), null, ((com.quizlet.themes.b) c0814p2.j(b2)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(b)).q, c0814p2, 0, 0, 65530);
            c0814p = c0814p2;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 11, fVar, fVar2, qVar);
        }
    }

    public static final void b(kotlinx.collections.immutable.b bVar, boolean z, com.quizlet.explanations.solution.fragments.b bVar2, q qVar, U u, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1820189364);
        boolean z2 = z;
        com.quizlet.explanations.solution.fragments.b bVar3 = bVar2;
        U u2 = u;
        int i2 = i | (c0814p.h(bVar) ? 4 : 2) | (c0814p.g(z2) ? 32 : 16) | (c0814p.h(bVar3) ? 256 : 128) | (c0814p.f(qVar) ? 2048 : 1024) | (c0814p.h(u2) ? 16384 : 8192);
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0380d c0380d = AbstractC0398m.a;
            m.g.s();
            androidx.compose.foundation.layout.B bA = A.a(AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.h), androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
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
            c0814p.X(846993596);
            int i4 = 0;
            for (Object obj : bVar) {
                int i5 = i4 + 1;
                if (i4 < 0) {
                    kotlin.collections.B.p();
                    throw null;
                }
                c cVar = (c) obj;
                int i6 = i2 >> 3;
                c(cVar, z2, bVar3, u2, c0814p, (i6 & 7168) | (i2 & 1008));
                d dVar = cVar.c;
                c0814p.X(846998199);
                SimpleImage simpleImage = dVar.b;
                if (simpleImage != null) {
                    d(simpleImage, bVar2, null, null, c0814p, i6 & ContentType.LONG_FORM_ON_DEMAND, 12);
                }
                c0814p.p(false);
                c0814p.X(847001801);
                if (i4 != kotlin.collections.B.i(bVar)) {
                    Z1.e(null, DefinitionKt.NO_Float_VALUE, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.i(), c0814p, 0, 3);
                }
                c0814p.p(false);
                z2 = z;
                bVar3 = bVar2;
                u2 = u;
                i4 = i5;
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.listitems.b(bVar, z, bVar2, qVar, u, i);
        }
    }

    public static final void c(c cVar, boolean z, com.quizlet.explanations.solution.fragments.b bVar, U u, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.explanations.solution.fragments.b bVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-726511398);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(cVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.g(z) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            bVar2 = bVar;
            i2 |= c0814p.h(bVar2) ? 256 : 128;
        } else {
            bVar2 = bVar;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(u) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            boolean z2 = cVar.b;
            String str = cVar.a;
            if (!z2 || StringsKt.O(str)) {
                d dVar = cVar.c;
                SimpleImage simpleImage = dVar.a;
                if ((simpleImage != null ? simpleImage.a : null) == null && !StringsKt.O(str)) {
                    c0814p.X(-1875672188);
                    f(str, c0814p, 0);
                    c0814p.p(false);
                } else if (simpleImage != null) {
                    c0814p.X(-1875581668);
                    b bVar3 = b.b;
                    long jE = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e();
                    d(dVar.a, bVar2, bVar3, new C0853m(jE, 5, Build.VERSION.SDK_INT >= 29 ? C0854n.a.a(jE, 5) : new PorterDuffColorFilter(F.A(jE), F.E(5))), c0814p, ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | 384, 0);
                    c0814p.p(false);
                } else {
                    c0814p.X(-1875316432);
                    c0814p.p(false);
                }
            } else {
                c0814p.X(-1875809487);
                e(cVar, z, u, c0814p, ((i2 >> 3) & 896) | (i2 & 126));
                c0814p.p(false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new g(cVar, z, bVar, u, i);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x004f  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0054  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x006c  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x007c  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x007f  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0082  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0085  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0092  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00da  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00dc  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00e7  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00f3  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x0108  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x0140  */
    /* JADX WARN: Removed duplicated region for block: B:82:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void d(com.quizlet.data.model.SimpleImage r15, com.quizlet.explanations.solution.fragments.b r16, com.quizlet.explanations.solution.recyclerview.step.b r17, androidx.compose.ui.graphics.C0853m r18, androidx.compose.runtime.InterfaceC0806l r19, int r20, int r21) {
        /*
            Method dump skipped, instructions count: 332
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.explanations.solution.recyclerview.step.i.d(com.quizlet.data.model.SimpleImage, com.quizlet.explanations.solution.fragments.b, com.quizlet.explanations.solution.recyclerview.step.b, androidx.compose.ui.graphics.m, androidx.compose.runtime.l, int, int):void");
    }

    public static final void e(c cVar, boolean z, U u, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1844273775);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(cVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.g(z) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(u) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            String str = cVar.a;
            X0 x0 = AndroidCompositionLocals_androidKt.b;
            com.quizlet.qatex.c cVar2 = new com.quizlet.qatex.c(str, com.quizlet.themes.extensions.a.a((Context) c0814p.j(x0), R.attr.SysColorTextPrimary), AbstractC3187k5.c((Context) c0814p.j(x0), R.style.Body_B3), z);
            q qVarC = K0.c(n.b, 1.0f);
            c0814p.X(1178712946);
            boolean zH = ((i2 & 896) == 256) | c0814p.h(cVar);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new com.quizlet.data.repository.explanations.exercise.a(8, u, cVar);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3673m4.a(cVar2, qVarC, true, (Function0) objI, null, c0814p, 432, 16);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new f(cVar, z, u, i);
        }
    }

    public static final void f(String str, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1786305762);
        int i2 = i | (c0814p2.f(str) ? 4 : 2);
        if ((i2 & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            Q4.b(str, K0.c(n.b, 1.0f), ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(w.b)).o, c0814p, (i2 & 14) | 48, 0, 65528);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new h(str, i, 0);
        }
    }

    public static final void g(e item, q qVar, U u, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(item, "item");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(553835254);
        if ((((c0814p.h(item) ? 4 : 2) | i | (c0814p.f(qVar) ? 32 : 16) | (c0814p.h(u) ? 256 : 128)) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            q qVarG = N.G(K0.c(qVar, 1.0f), "SolutionStep");
            V vO = Z1.o(((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.n(), 0L, 0L, c0814p, 0, 14);
            m.g.c();
            Z1.c(qVarG, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.h), vO, Z1.p((float) 1.0d, 62), null, androidx.compose.runtime.internal.e.e(-1967753020, new com.quizlet.assembly.compose.input.m(3, item, u), c0814p), c0814p, 196608, 16);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 10, item, qVar, u);
        }
    }
}
