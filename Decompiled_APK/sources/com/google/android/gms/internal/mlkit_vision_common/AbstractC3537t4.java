package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y4;
import com.quizlet.learn.data.AbstractC4540e;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.t4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3537t4 {
    public static final void a(Integer num, Integer num2, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar;
        float f;
        boolean z;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1463844704);
        int i3 = i | (c0814p.f(num) ? 4 : 2) | (c0814p.f(num2) ? 32 : 16) | (c0814p.h(function0) ? 256 : 128) | (c0814p.h(function02) ? 2048 : 1024);
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(nVar2, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), androidx.compose.ui.graphics.F.a);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.i;
            mVar.q();
            mVar.q();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarF, f2, DefinitionKt.NO_Float_VALUE, f2, f2, 2);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.n, c0814p, 48);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarY);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(-509404235);
            if (num == null) {
                i2 = i3;
                nVar = nVar2;
                f = 1.0f;
            } else {
                int i5 = (i3 & 896) | 48;
                i2 = i3;
                nVar = nVar2;
                f = 1.0f;
                com.google.android.gms.internal.mlkit_vision_document_scanner.W4.a(AbstractC3106b5.d(c0814p, num.intValue()), androidx.compose.foundation.layout.K0.c(nVar2, 1.0f), function0, false, null, null, null, null, null, false, c0814p, i5, 1016);
                mVar.s();
                AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, com.quizlet.ui.resources.designsystem.generated.j.h));
            }
            c0814p.p(false);
            c0814p.X(-509392858);
            if (num2 == null) {
                z = false;
            } else {
                androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, f);
                z = false;
                Y4.b(AbstractC3106b5.d(c0814p, num2.intValue()), qVarC2, function02, false, null, null, 0L, 0L, null, null, null, c0814p, ((i2 >> 3) & 896) | 48, 0, 4088);
                c0814p = c0814p;
            }
            c0814p.p(z);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i(num, num2, function0, function02, i);
        }
    }

    public static final void b(androidx.compose.ui.graphics.painter.b bVar, int i, int i2, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i3) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1943005517);
        int i4 = i3 | (c0814p.h(bVar) ? 4 : 2) | (c0814p.d(i) ? 32 : 16) | (c0814p.d(i2) ? 256 : 128) | (c0814p.f(qVar) ? 2048 : 1024);
        if ((i4 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(qVar, ((com.quizlet.themes.b) c0814p.j(b)).b.g(), androidx.compose.ui.graphics.F.a);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            androidx.compose.ui.q qVarG = AbstractC0382e.u(qVarF, com.quizlet.ui.resources.designsystem.generated.j.i).g(androidx.compose.foundation.layout.K0.c);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g, androidx.compose.ui.b.n, c0814p, 54);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            mVar.l();
            AbstractC0460p.c(bVar, null, androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.k), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, (i4 & 14) | 48, 120);
            String strD = AbstractC3106b5.d(c0814p, i);
            long jE = ((com.quizlet.themes.b) c0814p.j(b)).b.e();
            androidx.compose.runtime.B b2 = com.quizlet.themes.w.a;
            androidx.compose.material3.Q4.b(strD, null, jE, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b2)).d, c0814p, 0, 0, 65018);
            mVar.s();
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, i2), AbstractC0382e.u(nVar, com.quizlet.ui.resources.designsystem.generated.j.h), ((com.quizlet.themes.b) c0814p.j(b)).b.f(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b2)).i, c0814p, 0, 0, 65016);
            c0814p = c0814p;
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.C.a(nVar, 1.0f));
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.n(bVar, i, i2, qVar, i3);
        }
    }

    public static final void c(int i, com.quizlet.learn.data.A viewState, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, Function0 function03, InterfaceC0806l interfaceC0806l, int i2) {
        Intrinsics.checkNotNullParameter(viewState, "viewState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1935757288);
        int i3 = i2 | (c0814p.d(i) ? 4 : 2) | (c0814p.f(viewState) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128) | (c0814p.h(function0) ? 2048 : 1024) | (c0814p.h(function02) ? 16384 : 8192) | (c0814p.h(function03) ? 131072 : 65536);
        if ((74899 & i3) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else if (Intrinsics.b(viewState, com.quizlet.learn.data.z.a)) {
            c0814p.X(75790169);
            AbstractC3249r5.a(qVar, 0L, c0814p, (i3 >> 6) & 14, 2);
            c0814p.p(false);
        } else {
            if (!(viewState instanceof com.quizlet.learn.data.y)) {
                throw com.google.android.gms.measurement.internal.Z.j(75788710, c0814p, false);
            }
            c0814p.X(75792920);
            com.quizlet.learn.data.y yVar = (com.quizlet.learn.data.y) viewState;
            int i4 = i3 & 14;
            int i5 = i3 << 6;
            d(i, yVar.a, yVar.b, yVar.c, qVar, function0, function02, function03, c0814p, (i5 & 29360128) | i4 | (57344 & i5) | (458752 & i5) | (3670016 & i5));
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p(i, viewState, qVar, function0, function02, function03, i2);
        }
    }

    public static final void d(int i, AbstractC4540e abstractC4540e, boolean z, com.quizlet.learn.ui.g gVar, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, Function0 function03, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-438486866);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.d(i) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p.f(abstractC4540e) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p.g(z) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p.h(gVar) ? 2048 : 1024;
        }
        if ((i2 & 24576) == 0) {
            i3 |= c0814p.f(qVar) ? 16384 : 8192;
        }
        if ((196608 & i2) == 0) {
            i3 |= c0814p.h(function0) ? 131072 : 65536;
        }
        if ((1572864 & i2) == 0) {
            i3 |= c0814p.h(function02) ? 1048576 : 524288;
        }
        if ((12582912 & i2) == 0) {
            i3 |= c0814p.h(function03) ? 8388608 : 4194304;
        }
        if ((4793491 & i3) == 4793490 && c0814p.x()) {
            c0814p.Q();
        } else {
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            if (i == 0) {
                c0814p.X(-1214299819);
                e(abstractC4540e, z, gVar, qVar, function0, function02, function03, c0814p, (i3 >> 3) & 4194302);
                c0814p.p(false);
            } else {
                c0814p.X(-1214065676);
                f(abstractC4540e, z, gVar, qVar, function0, function02, function03, c0814p, (i3 >> 3) & 4194302);
                c0814p.p(false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.modals.o(i, i2, qVar, abstractC4540e, gVar, function0, function02, function03, z);
        }
    }

    public static final void e(AbstractC4540e abstractC4540e, boolean z, com.quizlet.learn.ui.g gVar, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, Function0 function03, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        boolean z2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1273151116);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(abstractC4540e) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            z2 = z;
            i2 |= c0814p.g(z2) ? 32 : 16;
        } else {
            z2 = z;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(gVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(qVar) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function0) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(function02) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p.h(function03) ? 1048576 : 524288;
        }
        if ((599187 & i2) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarG = AbstractC0460p.f(qVar, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), androidx.compose.ui.graphics.F.a).g(androidx.compose.foundation.layout.K0.c);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.h, false);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            int i4 = i2;
            AbstractC0725t3.a(null, null, androidx.compose.runtime.internal.e.e(-430434537, new com.quizlet.assembly.compose.cards.c(abstractC4540e, 25), c0814p), null, null, 0, 0L, 0L, null, androidx.compose.runtime.internal.e.e(-669403295, new com.quizlet.learn.ui.d(abstractC4540e, 0), c0814p), c0814p, 805306752, 507);
            c0814p = c0814p;
            c0814p.X(353669695);
            if (gVar != null) {
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                com.quizlet.themes.m.g.s();
                int i5 = i4 >> 3;
                AbstractC3543u4.a(gVar, z2, AbstractC0382e.u(nVar, com.quizlet.ui.resources.designsystem.generated.j.h), function0, function02, function03, c0814p, ((i4 >> 6) & 14) | (i4 & ContentType.LONG_FORM_ON_DEMAND) | (i5 & 7168) | (57344 & i5) | (i5 & 458752), 0);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.learn.ui.c(i, 1, qVar, abstractC4540e, gVar, function0, function02, function03, z);
        }
    }

    public static final void f(AbstractC4540e abstractC4540e, boolean z, com.quizlet.learn.ui.g gVar, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, Function0 function03, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-693587498);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(abstractC4540e) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.g(z) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(gVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(qVar) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function0) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(function02) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p.h(function03) ? 1048576 : 524288;
        }
        if ((599187 & i2) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            androidx.compose.ui.q qVarG = AbstractC0460p.f(qVar, ((com.quizlet.themes.b) c0814p.j(b)).b.g(), androidx.compose.ui.graphics.F.a).g(androidx.compose.foundation.layout.K0.c);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.h, false);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            int i4 = i2;
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            C0418x c0418x = C0418x.a;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.p();
            androidx.compose.material3.Z1.c(androidx.compose.foundation.layout.K0.c(c0418x.a(AbstractC0382e.w(nVar, com.quizlet.ui.resources.designsystem.generated.j.j, DefinitionKt.NO_Float_VALUE, 2), androidx.compose.ui.b.e), 1.0f), null, androidx.compose.material3.Z1.o(((com.quizlet.themes.b) c0814p.j(b)).b.n(), 0L, 0L, c0814p, 0, 14), androidx.compose.material3.Z1.p(com.quizlet.themes.m.j, 62), null, androidx.compose.runtime.internal.e.e(203146206, new com.quizlet.learn.ui.d(abstractC4540e, 1), c0814p), c0814p, 196608, 18);
            c0814p.X(-227012765);
            if (gVar != null) {
                mVar.s();
                int i5 = i4 >> 3;
                AbstractC3543u4.a(gVar, z, AbstractC0382e.u(nVar, com.quizlet.ui.resources.designsystem.generated.j.h), function0, function02, function03, c0814p, ((i4 >> 6) & 14) | (i4 & ContentType.LONG_FORM_ON_DEMAND) | (i5 & 7168) | (57344 & i5) | (i5 & 458752), 0);
                c0814p = c0814p;
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.learn.ui.c(i, 0, qVar, abstractC4540e, gVar, function0, function02, function03, z);
        }
    }

    public static HashSet g(Object... objArr) {
        int iCeil;
        int length = objArr.length;
        if (length < 3) {
            AbstractC3502n4.i(length, "expectedSize");
            iCeil = length + 1;
        } else {
            iCeil = length < 1073741824 ? (int) Math.ceil(length / 0.75d) : SubsamplingScaleImageView.TILE_SIZE_AUTO;
        }
        HashSet hashSet = new HashSet(iCeil);
        Collections.addAll(hashSet, objArr);
        return hashSet;
    }
}
