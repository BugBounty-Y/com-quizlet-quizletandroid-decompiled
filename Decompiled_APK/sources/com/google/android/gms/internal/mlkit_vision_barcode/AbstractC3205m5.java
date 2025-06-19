package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import android.util.DisplayMetrics;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0253l0;
import androidx.compose.animation.core.C0276z;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0377b0;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.foundation.layout.FillElement;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.comscore.streaming.ContentType;
import com.quizlet.features.achievements.ui.composables.C4218e;
import com.quizlet.quizletandroid.R;
import com.quizlet.ui.compose.EnumC4819l;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Set;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.m5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3205m5 {
    public static final void a(kotlinx.collections.immutable.e eVar, Function1 function1, androidx.compose.ui.q qVar, int i, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        int i4;
        boolean z;
        boolean z2;
        int i5;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1739033469);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.h(eVar) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p.h(function1) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= 1024;
        }
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            i5 = i;
        } else {
            c0814p.S();
            if ((i2 & 1) == 0 || c0814p.w()) {
                i4 = g(c0814p).a;
            } else {
                c0814p.Q();
                i4 = i;
            }
            c0814p.q();
            androidx.compose.foundation.N0 scrollState = AbstractC0460p.r(c0814p);
            androidx.compose.ui.i iVar = androidx.compose.ui.b.a;
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(iVar, false);
            int i6 = c0814p.P;
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
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, kE, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            C0418x c0418x = C0418x.a;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            float fJ = ((com.quizlet.themes.j) c0814p.j(com.quizlet.themes.l.a)).j();
            int i7 = i4;
            Intrinsics.checkNotNullParameter(scrollState, "scrollState");
            c0814p.X(-1658834464);
            androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f);
            C0276z c0276zA = androidx.compose.animation.p0.a(c0814p);
            float fC0 = bVar.c0(fJ);
            c0814p.X(375825493);
            boolean zC = c0814p.c(1000.0f) | c0814p.f(scrollState) | c0814p.c(fC0);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (zC || objI == v) {
                objI = new com.quizlet.ui.compose.util.e(scrollState, fC0);
                c0814p.i0(objI);
            }
            com.quizlet.ui.compose.util.e eVar2 = (com.quizlet.ui.compose.util.e) objI;
            c0814p.p(false);
            c0814p.X(375893460);
            boolean zF = c0814p.f(eVar2) | c0814p.f(c0276zA) | c0814p.c(400.0f);
            Object objI2 = c0814p.I();
            if (zF || objI2 == v) {
                C0253l0 c0253l0Q = AbstractC0240f.q(5, null);
                float f = androidx.compose.foundation.gestures.snapping.l.a;
                androidx.compose.foundation.gestures.snapping.h hVar = new androidx.compose.foundation.gestures.snapping.h(eVar2, c0276zA, c0253l0Q);
                c0814p.i0(hVar);
                objI2 = hVar;
            }
            c0814p.p(false);
            c0814p.p(false);
            AbstractC0377b0.a(AbstractC0460p.o(nVar, scrollState, (androidx.compose.foundation.gestures.snapping.h) objI2, 10), null, null, 2, 0, null, androidx.compose.runtime.internal.e.e(981858782, new com.quizlet.assembly.compose.input.m(15, eVar, function1), c0814p), c0814p, 1575936);
            c0814p = c0814p;
            c0814p.X(540329541);
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            if (i7 == 0) {
                z2 = true;
                z = false;
            } else {
                androidx.compose.ui.q qVarB = c0418x.b(nVar);
                androidx.compose.ui.layout.K kE2 = AbstractC0409s.e(iVar, false);
                int i8 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
                androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarB);
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, kE2, c0912h);
                C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                    android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h3);
                }
                C0776c.E(c0814p, qVarC2, c0912h4);
                c0814p.X(-233914627);
                if (scrollState.g() > 0) {
                    long jG = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g();
                    EnumC4819l enumC4819l = EnumC4819l.b;
                    FillElement fillElement = androidx.compose.foundation.layout.K0.b;
                    mVar.v();
                    AbstractC3241q5.a(androidx.compose.ui.platform.N.G(c0418x.a(androidx.compose.foundation.layout.K0.q(fillElement, com.quizlet.ui.resources.designsystem.generated.j.l, DefinitionKt.NO_Float_VALUE, 2), androidx.compose.ui.b.d), "home_recents_start_gradient"), jG, 0L, enumC4819l, c0814p, 3072, 4);
                }
                c0814p.p(false);
                c0814p.X(-233896578);
                if (scrollState.g() < scrollState.f()) {
                    long jG2 = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g();
                    FillElement fillElement2 = androidx.compose.foundation.layout.K0.b;
                    mVar.v();
                    AbstractC3241q5.a(androidx.compose.ui.platform.N.G(c0418x.a(androidx.compose.foundation.layout.K0.q(fillElement2, com.quizlet.ui.resources.designsystem.generated.j.l, DefinitionKt.NO_Float_VALUE, 2), androidx.compose.ui.b.f), "home_recents_end_gradient"), 0L, jG2, null, c0814p, 0, 10);
                }
                z = false;
                c0814p.p(false);
                z2 = true;
                c0814p.p(true);
            }
            c0814p.p(z);
            c0814p.p(z2);
            i5 = i7;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4218e(i5, i2, 1, qVar, (Object) eVar, (Object) function1);
        }
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function1 function1, kotlinx.collections.immutable.e items) {
        Intrinsics.checkNotNullParameter(items, "items");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1518024769);
        int i2 = (c0814p.h(items) ? 4 : 2) | i | (c0814p.f(qVar) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
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
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p, R.string.home_recents_section_title);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            AbstractC3214n5.b(strD, AbstractC0382e.y(nVar, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), c0814p, 0);
            mVar.q();
            a(items, function1, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 0, c0814p, (i2 & 14) | ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND));
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.home.composables.sections.c(items, qVar, function1, i);
        }
    }

    public static final long c(int i, int i2) {
        if (i < 0) {
            throw new IllegalArgumentException(("start cannot be negative. [start: " + i + ", end: " + i2 + ']').toString());
        }
        if (i2 >= 0) {
            long j = (i2 & 4294967295L) | (i << 32);
            int i3 = androidx.compose.ui.text.K.c;
            return j;
        }
        throw new IllegalArgumentException(("end cannot be negative. [start: " + i + ", end: " + i2 + ']').toString());
    }

    public static final long d(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        DisplayMetrics displayMetrics = context.getResources().getDisplayMetrics();
        float f = displayMetrics.widthPixels;
        float f2 = displayMetrics.density;
        return N5.c(f / f2, displayMetrics.heightPixels / f2);
    }

    public static final androidx.compose.material3.windowsizeclass.b e(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        return com.quizlet.shared.usecase.folderstudymaterials.a.m(d(context));
    }

    public static final long f(int i, long j) {
        int i2 = androidx.compose.ui.text.K.c;
        int i3 = (int) (j >> 32);
        int iC = kotlin.ranges.l.c(i3, 0, i);
        int i4 = (int) (4294967295L & j);
        int iC2 = kotlin.ranges.l.c(i4, 0, i);
        return (iC == i3 && iC2 == i4) ? j : c(iC, iC2);
    }

    public static final androidx.compose.material3.windowsizeclass.b g(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.j(AndroidCompositionLocals_androidKt.a);
        return e((Context) c0814p.j(AndroidCompositionLocals_androidKt.b));
    }
}
