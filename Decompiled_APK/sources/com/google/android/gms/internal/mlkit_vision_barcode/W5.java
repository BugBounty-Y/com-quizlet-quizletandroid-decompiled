package com.google.android.gms.internal.mlkit_vision_barcode;

import android.view.View;
import androidx.compose.material3.C0674l;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0810n;
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
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.comscore.streaming.ContentType;
import com.quizlet.data.model.School;
import com.quizlet.data.model.Textbook;
import java.util.UUID;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class W5 {
    public static final void a(Function0 function0, androidx.compose.ui.window.r rVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        int i3;
        int i4;
        androidx.compose.ui.unit.k kVar;
        Object o;
        Function0 function02 = function0;
        androidx.compose.ui.window.r rVar2 = rVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2032877254);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function02) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(rVar2) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(dVar) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            View view = (View) c0814p.j(AndroidCompositionLocals_androidKt.f);
            androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f);
            androidx.compose.ui.unit.k kVar2 = (androidx.compose.ui.unit.k) c0814p.j(AbstractC0955m0.l);
            C0810n c0810nC = C0776c.C(c0814p);
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D(dVar, c0814p);
            UUID uuid = (UUID) L4.d(new Object[0], null, androidx.compose.ui.window.d.b, c0814p, 3072, 6);
            boolean zF = c0814p.f(view) | c0814p.f(bVar);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (zF || objI == v) {
                i3 = i2;
                i4 = 32;
                kVar = kVar2;
                androidx.compose.ui.window.s sVar = new androidx.compose.ui.window.s(function02, rVar2, view, kVar, bVar, uuid);
                androidx.compose.runtime.internal.d dVar2 = new androidx.compose.runtime.internal.d(true, 488261145, new C0674l(interfaceC0773a0D, 4));
                androidx.compose.ui.window.q qVar = sVar.g;
                qVar.setParentCompositionContext(c0810nC);
                ((androidx.compose.runtime.L0) qVar.b).setValue(dVar2);
                qVar.d = true;
                qVar.createComposition();
                c0814p.i0(sVar);
                objI = sVar;
            } else {
                i3 = i2;
                i4 = 32;
                kVar = kVar2;
            }
            androidx.compose.ui.window.s sVar2 = (androidx.compose.ui.window.s) objI;
            boolean zH = c0814p.h(sVar2);
            Object objI2 = c0814p.I();
            if (zH || objI2 == v) {
                objI2 = new androidx.compose.ui.window.b(sVar2, 0);
                c0814p.i0(objI2);
            }
            C0776c.d(sVar2, (Function1) objI2, c0814p);
            boolean zH2 = c0814p.h(sVar2) | ((i3 & 14) == 4) | ((i3 & ContentType.LONG_FORM_ON_DEMAND) == i4) | c0814p.f(kVar);
            Object objI3 = c0814p.I();
            if (zH2 || objI3 == v) {
                o = new androidx.compose.animation.core.O(sVar2, function0, rVar, kVar, 6);
                function02 = function0;
                rVar2 = rVar;
                c0814p.i0(o);
            } else {
                function02 = function0;
                o = objI3;
                rVar2 = rVar;
            }
            C0776c.i((Function0) o, c0814p);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.contextmenu.a(function02, rVar2, dVar, i);
        }
    }

    public static final void b(androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1177876616);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(dVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.window.e eVar = androidx.compose.ui.window.e.b;
            int i3 = ((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND) | ((i2 >> 3) & 14) | 384;
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            int i5 = ((i3 << 6) & 896) | 6;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, eVar, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.animation.d0.w((i5 >> 6) & 14, dVar, c0814p, true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.animation.core.D0(qVar, dVar, i, 13);
        }
    }

    public static final com.quizlet.ui.models.content.listitem.p c(Textbook textbook) {
        Intrinsics.checkNotNullParameter(textbook, "<this>");
        return new com.quizlet.ui.models.content.listitem.p(textbook.b, textbook.c, textbook.e, textbook.h);
    }

    public static final com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e d(School school) {
        Intrinsics.checkNotNullParameter(school, "<this>");
        return new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e(school.a, school.i, school.b + ", " + school.j, null, 56);
    }
}
