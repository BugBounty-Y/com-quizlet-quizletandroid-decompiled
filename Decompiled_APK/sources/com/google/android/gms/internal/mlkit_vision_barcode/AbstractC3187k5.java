package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.pager.C0466e;
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
import com.comscore.streaming.ContentType;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.k5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3187k5 {
    public static final void a(kotlinx.collections.immutable.e eVar, Function0 function0, Function1 function1, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1326651234);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(eVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function1) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.f(qVar) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.X(1015349765);
            boolean zH = c0814p2.h(eVar);
            Object objI = c0814p2.I();
            if (zH || objI == C0804k.a) {
                objI = new com.quizlet.features.home.composables.sections.a(eVar, 0);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            C0466e c0466eB = androidx.compose.foundation.pager.I.b(0, (Function0) objI, c0814p2, 0, 3);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.foundation.layout.A0 a0C = AbstractC0382e.c(f, DefinitionKt.NO_Float_VALUE, 2);
            mVar.s();
            c0814p = c0814p2;
            AbstractC3191l0.a(f, 0, (i2 >> 6) & ContentType.LONG_FORM_ON_DEMAND, 8152, null, null, a0C, null, c0466eB, null, c0814p, androidx.compose.runtime.internal.e.e(-1983993152, new com.quizlet.features.home.composables.sections.b(eVar, function0, function1, 0), c0814p2), null, qVar, false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i((Object) eVar, (Object) function0, (Object) function1, qVar, i, 10);
        }
    }

    public static final void b(kotlinx.collections.immutable.e items, Function0 onCardMenuClick, Function1 onProgressItemCtaButtonClick, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter("Jump back in", "sectionTitle");
        Intrinsics.checkNotNullParameter(items, "items");
        Intrinsics.checkNotNullParameter(onCardMenuClick, "onCardMenuClick");
        Intrinsics.checkNotNullParameter(onProgressItemCtaButtonClick, "onProgressItemCtaButtonClick");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1277098028);
        int i2 = i | (c0814p2.h(items) ? 32 : 16) | (c0814p2.h(onProgressItemCtaButtonClick) ? 2048 : 1024) | (c0814p2.f(qVar) ? 16384 : 8192);
        if ((i2 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(qVar, 1.0f), "home_progress_section");
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p2, 0);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVarG);
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
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p2, i3, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            AbstractC3214n5.b("Jump back in", AbstractC0382e.y(nVar, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), c0814p2, 6);
            mVar.q();
            c0814p = c0814p2;
            a(items, onCardMenuClick, onProgressItemCtaButtonClick, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, (i2 >> 3) & 1022);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i(items, onCardMenuClick, onProgressItemCtaButtonClick, qVar, i, 11);
        }
    }

    public static final float c(Context context, int i) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(context, "<this>");
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(i, com.quizlet.themes.u.g);
        Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
        float dimension = typedArrayObtainStyledAttributes.getDimension(0, -1.0f);
        typedArrayObtainStyledAttributes.recycle();
        return dimension;
    }

    public static final androidx.compose.ui.text.J d(C0814p c0814p) {
        androidx.compose.ui.text.font.i iVar = (androidx.compose.ui.text.font.i) c0814p.j(AbstractC0955m0.i);
        androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f);
        androidx.compose.ui.unit.k kVar = (androidx.compose.ui.unit.k) c0814p.j(AbstractC0955m0.l);
        boolean zF = c0814p.f(iVar) | c0814p.f(bVar) | c0814p.f(kVar) | c0814p.d(8);
        Object objI = c0814p.I();
        if (zF || objI == C0804k.a) {
            objI = new androidx.compose.ui.text.J(iVar, bVar, kVar);
            c0814p.i0(objI);
        }
        return (androidx.compose.ui.text.J) objI;
    }
}
