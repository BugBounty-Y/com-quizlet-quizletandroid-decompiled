package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.navigation.compose.C1278k;
import androidx.navigation.compose.C1280m;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3182k0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3737u5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Iterator;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.k0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3182k0 {
    public static final void a(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1029455558);
        if ((((c0814p.f(qVar) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarG = androidx.compose.foundation.layout.K0.c(qVar, 1.0f).g(androidx.compose.foundation.layout.K0.b);
            com.quizlet.themes.m.g.t();
            androidx.compose.ui.q qVarU = AbstractC0382e.u(qVarG, com.quizlet.ui.resources.designsystem.generated.j.k);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.e, androidx.compose.ui.b.n, c0814p, 54);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarU);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.empty_search), androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "noResults"), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).f, c0814p, 48, 0, 65016);
            c0814p = c0814p;
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            AbstractC0382e.f(c0814p, new androidx.compose.foundation.layout.N(C0380d.e(c0814p).c));
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 24, qVar);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:175:0x02a7  */
    /* JADX WARN: Removed duplicated region for block: B:217:0x0325 A[PHI: r5
  0x0325: PHI (r5v67 androidx.compose.foundation.pager.l) = (r5v47 androidx.compose.foundation.pager.l), (r5v68 androidx.compose.foundation.pager.l) binds: [B:216:0x0323, B:212:0x031c] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:221:0x0331  */
    /* JADX WARN: Removed duplicated region for block: B:224:0x033c  */
    /* JADX WARN: Removed duplicated region for block: B:227:0x0344 A[PHI: r49
  0x0344: PHI (r49v5 boolean) = (r49v3 boolean), (r49v6 boolean) binds: [B:226:0x0342, B:222:0x0339] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:228:0x0347  */
    /* JADX WARN: Removed duplicated region for block: B:231:0x035a  */
    /* JADX WARN: Removed duplicated region for block: B:234:0x0363  */
    /* JADX WARN: Removed duplicated region for block: B:237:0x0369 A[PHI: r13
  0x0369: PHI (r13v39 int) = (r13v29 int), (r13v40 int) binds: [B:236:0x0367, B:232:0x0360] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:238:0x036c  */
    /* JADX WARN: Removed duplicated region for block: B:241:0x037b A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:242:0x037d  */
    /* JADX WARN: Removed duplicated region for block: B:256:0x03c9 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:257:0x03cb  */
    /* JADX WARN: Removed duplicated region for block: B:260:0x03da  */
    /* JADX WARN: Removed duplicated region for block: B:261:0x03dd  */
    /* JADX WARN: Removed duplicated region for block: B:264:0x03e4  */
    /* JADX WARN: Removed duplicated region for block: B:265:0x03e7  */
    /* JADX WARN: Removed duplicated region for block: B:271:0x03f5  */
    /* JADX WARN: Removed duplicated region for block: B:274:0x040d  */
    /* JADX WARN: Removed duplicated region for block: B:275:0x0410  */
    /* JADX WARN: Removed duplicated region for block: B:279:0x041e  */
    /* JADX WARN: Removed duplicated region for block: B:282:0x0443  */
    /* JADX WARN: Removed duplicated region for block: B:283:0x0453  */
    /* JADX WARN: Removed duplicated region for block: B:294:0x047b  */
    /* JADX WARN: Removed duplicated region for block: B:296:0x0481  */
    /* JADX WARN: Removed duplicated region for block: B:302:0x0490 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:303:0x0492  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(float r39, int r40, int r41, int r42, androidx.compose.foundation.gestures.snapping.h r43, androidx.compose.foundation.gestures.snapping.n r44, androidx.compose.foundation.layout.A0 r45, androidx.compose.foundation.pager.C0462a r46, androidx.compose.foundation.pager.C0466e r47, androidx.compose.foundation.pager.l r48, androidx.compose.runtime.InterfaceC0806l r49, androidx.compose.runtime.internal.d r50, androidx.compose.ui.h r51, androidx.compose.ui.q r52, boolean r53) {
        /*
            Method dump skipped, instructions count: 1315
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3182k0.b(float, int, int, int, androidx.compose.foundation.gestures.snapping.h, androidx.compose.foundation.gestures.snapping.n, androidx.compose.foundation.layout.A0, androidx.compose.foundation.pager.a, androidx.compose.foundation.pager.e, androidx.compose.foundation.pager.l, androidx.compose.runtime.l, androidx.compose.runtime.internal.d, androidx.compose.ui.h, androidx.compose.ui.q, boolean):void");
    }

    public static final void c(kotlinx.collections.immutable.b bVar, InterfaceC0806l interfaceC0806l, int i) {
        long jR;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(135414127);
        if ((((c0814p.f(bVar) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m.g.u();
            C0392j c0392jG = AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.g);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0392jG, androidx.compose.ui.b.m, c0814p, 0);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(-263927329);
            Iterator<E> it2 = bVar.iterator();
            while (it2.hasNext()) {
                com.quizlet.assembly.widgets.progress.c cVar = (com.quizlet.assembly.widgets.progress.c) it2.next();
                String strD = AbstractC3106b5.d(c0814p, cVar.a);
                c0814p.X(-297026386);
                int iOrdinal = cVar.c.ordinal();
                if (iOrdinal == 0) {
                    c0814p.X(-576503429);
                    jR = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).r0;
                    c0814p.p(false);
                } else if (iOrdinal == 1) {
                    c0814p.X(-576500124);
                    jR = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).s0;
                    c0814p.p(false);
                } else {
                    if (iOrdinal != 2) {
                        throw com.google.android.gms.measurement.internal.Z.j(-576505896, c0814p, false);
                    }
                    c0814p.X(-576496885);
                    jR = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).r();
                    c0814p.p(false);
                }
                c0814p.p(false);
                d(strD, cVar.b, jR, c0814p, 0);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(bVar, i, 11);
        }
    }

    public static final void d(final String str, final int i, final long j, InterfaceC0806l interfaceC0806l, final int i2) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1724897405);
        int i3 = i2 | (c0814p2.f(str) ? 4 : 2) | (c0814p2.d(i) ? 32 : 16) | (c0814p2.e(j) ? 256 : 128);
        if ((i3 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(androidx.compose.ui.n.b, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.b();
            androidx.compose.ui.q qVarF = AbstractC0460p.f(qVarC, j, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.j));
            mVar.n();
            float f = com.quizlet.ui.resources.designsystem.generated.j.o;
            mVar.f.getClass();
            androidx.compose.ui.q qVarV = AbstractC0382e.v(qVarF, f, com.quizlet.ui.resources.designsystem.generated.j.m);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g, androidx.compose.ui.b.j, c0814p2, 6);
            int i4 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p2, qVarV);
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
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p2, i4, c0912h);
            }
            C0776c.E(c0814p2, qVarC2, C0914j.d);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jV = ((com.quizlet.themes.b) c0814p2.j(b)).v();
            androidx.compose.runtime.B b2 = com.quizlet.themes.w.a;
            androidx.compose.material3.Q4.b(str, null, jV, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(b2)).k, c0814p2, i3 & 14, 0, 65530);
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(String.valueOf(i), null, ((com.quizlet.themes.b) c0814p.j(b)).v(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b2)).k, c0814p, 0, 0, 65530);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(j, i, i2, str) { // from class: com.quizlet.features.flashcards.screens.g
                public final /* synthetic */ String a;
                public final /* synthetic */ int b;
                public final /* synthetic */ long c;

                {
                    this.a = str;
                }

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    int i5 = this.b;
                    long j2 = this.c;
                    AbstractC3182k0.d(this.a, i5, j2, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void e(com.quizlet.assembly.widgets.progress.d progressViewState, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(progressViewState, "progressViewState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(450138762);
        if ((((c0814p.h(progressViewState) ? 4 : 2) | i | 48) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p, 48);
            int i2 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            AbstractC3737u5.a(progressViewState.a(), progressViewState.c(), null, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0L, 0L, c0814p, 0, 124);
            com.quizlet.themes.m.g.p();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.o(nVar, com.quizlet.ui.resources.designsystem.generated.j.j));
            c(AbstractC3409x1.i(progressViewState.a), c0814p, 0);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(progressViewState, nVar, i, 13);
        }
    }
}
