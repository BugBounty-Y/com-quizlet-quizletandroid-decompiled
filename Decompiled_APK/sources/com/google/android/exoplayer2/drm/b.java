package com.google.android.exoplayer2.drm;

import android.content.Context;
import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import androidx.compose.animation.core.J0;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.A;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.B;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.foundation.layout.K0;
import androidx.compose.foundation.lazy.grid.C0426a;
import androidx.compose.material3.Q4;
import androidx.compose.material3.Z1;
import androidx.compose.material3.windowsizeclass.c;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.runtime.internal.e;
import androidx.compose.ui.graphics.C0850j;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.C0854n;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.layout.C0888i;
import androidx.compose.ui.n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.compose.ui.platform.N;
import androidx.compose.ui.q;
import androidx.compose.ui.text.style.i;
import androidx.navigation.U;
import androidx.navigation.compose.C1278k;
import androidx.navigation.compose.C1280m;
import androidx.navigation.compose.u;
import com.google.android.gms.internal.measurement.AbstractC3058t1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3155h0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3223o5;
import com.google.android.gms.internal.mlkit_vision_barcode.O4;
import com.google.android.gms.internal.mlkit_vision_barcode.S4;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.R4;
import com.quizlet.assembly.compose.buttons.C4084i;
import com.quizlet.data.model.C4114c;
import com.quizlet.data.model.C4166t;
import com.quizlet.data.model.J1;
import com.quizlet.data.model.L1;
import com.quizlet.data.model.O;
import com.quizlet.features.achievements.ui.composables.v;
import com.quizlet.features.achievements.ui.composables.x;
import com.quizlet.quizletandroid.R;
import com.quizlet.qutils.string.g;
import com.quizlet.themes.f;
import com.quizlet.themes.m;
import com.quizlet.themes.w;
import com.quizlet.ui.resources.designsystem.generated.h;
import com.quizlet.ui.resources.designsystem.generated.j;
import com.quizlet.ui.resources.icons.d;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Set;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class b {
    public static final void a(C4166t achievementsRecentsItem, n nVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        n nVar2;
        Intrinsics.checkNotNullParameter(achievementsRecentsItem, "achievementsRecentsItem");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1962458699);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(achievementsRecentsItem) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        int i3 = i2 | 48;
        if ((i & 384) == 0) {
            i3 |= c0814p2.h(function1) ? 256 : 128;
        }
        if ((i3 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            n nVar3 = n.b;
            m mVar = m.g;
            androidx.compose.material3.windowsizeclass.b bVarG = AbstractC3205m5.g(c0814p2);
            Set set = c.b;
            float fA = AbstractC3223o5.a(c0814p2, bVarG.a == 2 ? 5 : 2);
            mVar.t();
            c0814p = c0814p2;
            R4.a(nVar3, null, 0L, 0L, 0L, null, false, null, null, null, e.e(-1559970245, new com.quizlet.assembly.compose.tags.c(achievementsRecentsItem, fA - j.k, function1), c0814p2), c0814p, (i3 >> 3) & 14, 1022);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new u(i, 8, achievementsRecentsItem, nVar2, function1);
        }
    }

    public static final void b(int i, int i2, long j, InterfaceC0806l interfaceC0806l, q qVar, String str) {
        q qVar2;
        int i3;
        C0814p c0814p;
        q qVar3;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(553574201);
        int i4 = i | (c0814p2.f(str) ? 4 : 2) | (c0814p2.e(j) ? 32 : 16);
        int i5 = i2 & 4;
        if (i5 != 0) {
            i3 = i4 | 384;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i3 = i4 | (c0814p2.f(qVar2) ? 256 : 128);
        }
        if ((i3 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            qVar3 = qVar2;
        } else {
            q qVar4 = i5 != 0 ? n.b : qVar2;
            m.g.u();
            c0814p = c0814p2;
            Q4.b(str, K0.r(AbstractC0382e.u(qVar4, j.g), 2), j, 0L, null, 0L, new i(3), 0L, 0, false, 0, 0, null, ((f) c0814p2.j(w.b)).l, c0814p, (i3 & 14) | ((i3 << 3) & 896), 0, 65016);
            qVar3 = qVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new x(str, j, qVar3, i, i2);
        }
    }

    public static final void c(J1 j1, q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(650923199);
        if ((((c0814p.h(j1) ? 4 : 2) | i | (c0814p.f(qVar) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            m mVar = m.g;
            B bA = A.a(AbstractC0398m.e, androidx.compose.ui.b.n, c0814p, 54);
            int i2 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            String strC = AbstractC3106b5.c(R.string.achievements_calendar_title, new Object[]{j1.a, j1.b}, c0814p);
            n nVar = n.b;
            mVar.g();
            com.facebook.appevents.codeless.i.a(0, 0, c0814p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, h.h, 7), strC);
            int size = (j1.c.size() / 7) * 48;
            C0426a c0426a = new C0426a(7);
            mVar.s();
            C0392j c0392jG = AbstractC0398m.g(j.h);
            q qVarG = N.G(K0.d(K0.o(nVar, m.s), size), "calendar_achievements");
            c0814p.X(323061201);
            boolean zH = c0814p.h(j1);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new U(j1, 27);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3155h0.b(c0426a, qVarG, null, null, c0392jG, null, null, false, (Function1) objI, c0814p, 0, 476);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(j1, qVar, i, 10);
        }
    }

    public static final void d(long j, q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2076975769);
        if ((((c0814p.e(j) ? 4 : 2) | i | (c0814p.f(qVar) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            m mVar = m.g;
            com.quizlet.themes.e.a(c0814p).f.getClass();
            androidx.compose.ui.graphics.painter.b bVarQ = d.q(c0814p);
            n nVar = n.b;
            mVar.i();
            AbstractC0460p.c(bVarQ, null, qVar.g(K0.c(K0.k(nVar, h.f), 1.0f)), null, null, DefinitionKt.NO_Float_VALUE, new C0853m(j, 5, Build.VERSION.SDK_INT >= 29 ? C0854n.a.a(j, 5) : new PorterDuffColorFilter(F.A(j), F.E(5))), c0814p, 48, 56);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4084i(i, 1, j, qVar);
        }
    }

    public static final void e(L1 streakStatusData, q qVar, InterfaceC0806l interfaceC0806l, int i) {
        g dVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(252714165);
        int i2 = (c0814p.h(streakStatusData) ? 4 : 2) | i | (c0814p.f(qVar) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            m mVar = m.g;
            B bA = A.a(AbstractC0398m.e, androidx.compose.ui.b.n, c0814p, 54);
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
            com.facebook.appevents.codeless.i.a(0, 2, c0814p, null, AbstractC3106b5.d(c0814p, R.string.achievements_current_streak_title));
            Intrinsics.checkNotNullParameter(streakStatusData, "streakStatusData");
            int i4 = com.quizlet.features.achievements.helper.a.a[streakStatusData.b.ordinal()];
            int i5 = streakStatusData.a;
            switch (i4) {
                case 1:
                case 2:
                    dVar = new com.quizlet.qutils.string.d(R.plurals.achievements_current_streak_days, i5, kotlin.collections.A.b(Integer.valueOf(i5)));
                    break;
                case 3:
                case 4:
                    dVar = new com.quizlet.qutils.string.d(R.plurals.achievements_current_streak_weeks, i5, kotlin.collections.A.b(Integer.valueOf(i5)));
                    break;
                case 5:
                    dVar = new com.quizlet.qutils.string.f(R.string.achievements_current_streak_no_progress, null);
                    break;
                case 6:
                case 7:
                case 8:
                case 9:
                    throw new IllegalStateException("Invalid AchievementsBadgeGoalType: " + streakStatusData + ".type");
                default:
                    throw new NoWhenBranchMatchedException();
            }
            String strA = dVar.a((Context) c0814p.j(AndroidCompositionLocals_androidKt.b));
            n nVar = n.b;
            mVar.q();
            float f = j.i;
            mVar.u();
            com.facebook.appevents.cloudbridge.c.a(strA, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, j.g, DefinitionKt.NO_Float_VALUE, f, 5), c0814p, 0);
            j(streakStatusData, c0814p, i2 & 14);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(streakStatusData, qVar, i, 9);
        }
    }

    public static final void f(O o, InterfaceC0806l interfaceC0806l, int i) {
        long jB;
        long jU;
        n nVar;
        q qVarH;
        q qVarH2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(54905104);
        if ((((c0814p.h(o) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            m mVar = m.g;
            c0814p.X(-563349114);
            final long j = o.g ? ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).U : C0861v.f;
            c0814p.p(false);
            androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f);
            mVar.p();
            float fC0 = bVar.c0(j.j);
            long jC = com.google.android.gms.internal.mlkit_vision_barcode.Q4.c(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
            long jA = T4.a(135.0f, fC0);
            long jA2 = O4.a(100.0f, 100.0f);
            c0814p.X(1014002393);
            final C0850j c0850jH = F.h();
            androidx.compose.ui.graphics.O.b(c0850jH, S4.c(com.google.android.gms.internal.mlkit_vision_barcode.R4.a(jC, jA), jA2, 0L, 0L, jA2, 12));
            c0814p.p(false);
            n nVar2 = n.b;
            c0814p.X(-563331576);
            boolean zH = c0814p.h(c0850jH) | c0814p.e(j);
            Object objI = c0814p.I();
            V v = C0804k.a;
            if (zH || objI == v) {
                final int i2 = 0;
                objI = new Function1() { // from class: com.quizlet.features.achievements.ui.composables.u
                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) {
                        switch (i2) {
                            case 0:
                                androidx.compose.ui.graphics.drawscope.d drawBehind = (androidx.compose.ui.graphics.drawscope.d) obj;
                                Intrinsics.checkNotNullParameter(drawBehind, "$this$drawBehind");
                                androidx.compose.ui.graphics.drawscope.d.j(drawBehind, c0850jH, j, DefinitionKt.NO_Float_VALUE, null, 60);
                                break;
                            default:
                                androidx.compose.ui.graphics.drawscope.d drawBehind2 = (androidx.compose.ui.graphics.drawscope.d) obj;
                                Intrinsics.checkNotNullParameter(drawBehind2, "$this$drawBehind");
                                androidx.compose.ui.graphics.drawscope.d.j(drawBehind2, c0850jH, j, DefinitionKt.NO_Float_VALUE, null, 60);
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p.i0(objI);
            }
            c0814p.p(false);
            q qVarE = androidx.compose.ui.draw.g.e(nVar2, (Function1) objI);
            c0814p.X(439934681);
            final C0850j c0850jH2 = F.h();
            androidx.compose.ui.graphics.O.b(c0850jH2, S4.c(com.google.android.gms.internal.mlkit_vision_barcode.R4.a(jC, jA), 0L, jA2, jA2, 0L, 18));
            c0814p.p(false);
            c0814p.X(-563322713);
            boolean zH2 = c0814p.h(c0850jH2) | c0814p.e(j);
            Object objI2 = c0814p.I();
            if (zH2 || objI2 == v) {
                final int i3 = 1;
                objI2 = new Function1() { // from class: com.quizlet.features.achievements.ui.composables.u
                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) {
                        switch (i3) {
                            case 0:
                                androidx.compose.ui.graphics.drawscope.d drawBehind = (androidx.compose.ui.graphics.drawscope.d) obj;
                                Intrinsics.checkNotNullParameter(drawBehind, "$this$drawBehind");
                                androidx.compose.ui.graphics.drawscope.d.j(drawBehind, c0850jH2, j, DefinitionKt.NO_Float_VALUE, null, 60);
                                break;
                            default:
                                androidx.compose.ui.graphics.drawscope.d drawBehind2 = (androidx.compose.ui.graphics.drawscope.d) obj;
                                Intrinsics.checkNotNullParameter(drawBehind2, "$this$drawBehind");
                                androidx.compose.ui.graphics.drawscope.d.j(drawBehind2, c0850jH2, j, DefinitionKt.NO_Float_VALUE, null, 60);
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            q qVarE2 = androidx.compose.ui.draw.g.e(nVar2, (Function1) objI2);
            q qVarF = AbstractC0460p.f(nVar2, j, F.a);
            if (!o.b) {
                qVarE = o.c ? qVarE2 : qVarF;
            }
            boolean z = o.f;
            if (z) {
                c0814p.X(-282688517);
                jB = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).X;
                c0814p.p(false);
            } else if (o.e) {
                c0814p.X(-282595455);
                jB = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f();
                c0814p.p(false);
            } else {
                c0814p.X(-282533114);
                jB = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.b();
                c0814p.p(false);
            }
            if (!AbstractC0460p.q(c0814p) || z) {
                c0814p.X(-282322841);
                jU = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).u();
                c0814p.p(false);
            } else {
                c0814p.X(-282379385);
                jU = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).r();
                c0814p.p(false);
            }
            mVar.g();
            q qVarD = K0.d(qVarE, h.h);
            com.quizlet.themes.e.a(c0814p).d.getClass();
            androidx.compose.ui.graphics.painter.b bVarG = J0.G(c0814p);
            com.quizlet.themes.e.a(c0814p).f.getClass();
            androidx.compose.ui.graphics.painter.b bVarQ = d.q(c0814p);
            if (z) {
                nVar = nVar2;
                qVarH = androidx.compose.ui.draw.g.h(nVar, bVarG, new androidx.compose.ui.i(DefinitionKt.NO_Float_VALUE, 0.5f), C0888i.f, DefinitionKt.NO_Float_VALUE, null, 50);
            } else {
                nVar = nVar2;
                qVarH = nVar;
            }
            if (o.d) {
                qVarH2 = androidx.compose.ui.draw.g.h(nVar, bVarQ, new androidx.compose.ui.i(DefinitionKt.NO_Float_VALUE, 0.9f), C0888i.e, DefinitionKt.NO_Float_VALUE, new C0853m(jU, 5, Build.VERSION.SDK_INT >= 29 ? C0854n.a.a(jU, 5) : new PorterDuffColorFilter(F.A(jU), F.E(5))), 18);
            } else {
                qVarH2 = nVar;
            }
            b(0, 0, jB, c0814p, qVarD.g(qVarH).g(qVarH2), o.a);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(o, i, 6);
        }
    }

    public static final void g(final C4114c c4114c, final float f, final Function1 function1, final q qVar, InterfaceC0806l interfaceC0806l, final int i) {
        boolean z;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1725677516);
        int i2 = i | (c0814p.h(c4114c) ? 4 : 2) | (c0814p.c(f) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128) | (c0814p.f(qVar) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            m mVar = m.g;
            B bA = A.a(AbstractC0398m.e, androidx.compose.ui.b.n, c0814p, 54);
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
            com.facebook.appevents.codeless.i.a(0, 2, c0814p, null, AbstractC3106b5.d(c0814p, R.string.achievements_badge_recently_unlocked_header));
            n nVar = n.b;
            if (c4114c != null) {
                c0814p.X(-1502858460);
                mVar.u();
                com.facebook.appevents.cloudbridge.c.a(c4114c.d, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, 0);
                q qVarO = K0.o(nVar, f);
                mVar.q();
                q qVarY = AbstractC0382e.y(qVarO, DefinitionKt.NO_Float_VALUE, j.i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
                c0814p.X(-879749869);
                boolean zH = ((i2 & 896) == 256) | c0814p.h(c4114c);
                Object objI = c0814p.I();
                if (zH || objI == C0804k.a) {
                    objI = new com.quizlet.features.achievements.ui.composables.q(function1, c4114c, 3);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                AbstractC3058t1.a(c4114c, qVarY, DefinitionKt.NO_Float_VALUE, (Function0) objI, c0814p, i2 & 14, 4);
                c0814p.p(false);
                z = true;
            } else {
                c0814p.X(-1502323028);
                String strD = AbstractC3106b5.d(c0814p, R.string.achievements_badge_recently_unlocked_empty_title);
                mVar.u();
                com.facebook.appevents.cloudbridge.c.a(strD, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, 0);
                androidx.compose.ui.graphics.painter.b bVarA = Z4.a(AbstractC0460p.q(c0814p) ? 2131231593 : 2131230871, c0814p, 0);
                mVar.q();
                z = true;
                AbstractC0460p.c(bVarA, null, K0.k(N.G(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, j.i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), "empty_badge_image"), m.r), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 48, 120);
                c0814p.p(false);
            }
            c0814p.p(z);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(f, function1, qVar, i) { // from class: com.quizlet.features.achievements.ui.composables.w
                public final /* synthetic */ float b;
                public final /* synthetic */ Function1 c;
                public final /* synthetic */ androidx.compose.ui.q d;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    Function1 function12 = this.c;
                    androidx.compose.ui.q qVar2 = this.d;
                    com.google.android.exoplayer2.drm.b.g(this.a, this.b, function12, qVar2, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void h(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1520924000);
        if (i == 0 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.material3.windowsizeclass.b bVarG = AbstractC3205m5.g(c0814p);
            long jI = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.i();
            Set set = c.b;
            int i2 = bVarG.a;
            if (i2 == 0 || i2 == 1) {
                Z1.g(null, DefinitionKt.NO_Float_VALUE, jI, c0814p, 0, 3);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.x(i, 5);
        }
    }

    public static final void i(long j, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-710131077);
        if ((((c0814p.e(j) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            m mVar = m.g;
            com.quizlet.themes.e.a(c0814p).d.getClass();
            androidx.compose.ui.graphics.painter.b bVarG = J0.G(c0814p);
            n nVar = n.b;
            mVar.g();
            AbstractC0460p.c(bVarG, null, K0.k(nVar, h.h), null, null, DefinitionKt.NO_Float_VALUE, new C0853m(j, 5, Build.VERSION.SDK_INT >= 29 ? C0854n.a.a(j, 5) : new PorterDuffColorFilter(F.A(j), F.E(5))), c0814p, 48, 56);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new v(i, 1, j);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:72:0x02e8  */
    /* JADX WARN: Removed duplicated region for block: B:74:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void j(com.quizlet.data.model.L1 r24, androidx.compose.runtime.InterfaceC0806l r25, int r26) {
        /*
            Method dump skipped, instructions count: 752
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.drm.b.j(com.quizlet.data.model.L1, androidx.compose.runtime.l, int):void");
    }

    public static final void k(long j, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(257970902);
        if ((((c0814p.e(j) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            m mVar = m.g;
            androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_streak_shape_dash, c0814p, 0);
            n nVar = n.b;
            mVar.u();
            q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, j.g, 7);
            mVar.h();
            AbstractC0460p.c(bVarA, null, K0.k(qVarY, h.g), null, null, DefinitionKt.NO_Float_VALUE, new C0853m(j, 5, Build.VERSION.SDK_INT >= 29 ? C0854n.a.a(j, 5) : new PorterDuffColorFilter(F.A(j), F.E(5))), c0814p, 48, 56);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new v(i, 0, j);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:297:0x0507  */
    /* JADX WARN: Removed duplicated region for block: B:330:0x0597  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static androidx.camera.core.impl.i0 l(androidx.camera.camera2.internal.compat.k r14) {
        /*
            Method dump skipped, instructions count: 1507
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.drm.b.l(androidx.camera.camera2.internal.compat.k):androidx.camera.core.impl.i0");
    }

    public static final void m(io.reactivex.rxjava3.internal.operators.completable.d dVar, IllegalStateException t) {
        Intrinsics.checkNotNullParameter(dVar, "<this>");
        Intrinsics.checkNotNullParameter(t, "t");
        if (io.reactivex.rxjava3.internal.disposables.a.b((io.reactivex.rxjava3.disposables.b) dVar.get())) {
            return;
        }
        dVar.onError(t);
    }
}
