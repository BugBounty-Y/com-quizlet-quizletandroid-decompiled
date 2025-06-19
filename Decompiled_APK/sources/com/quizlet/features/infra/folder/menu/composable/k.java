package com.quizlet.features.infra.folder.menu.composable;

import androidx.compose.animation.E;
import androidx.compose.animation.V;
import androidx.compose.animation.a0;
import androidx.compose.animation.b0;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.foundation.layout.A;
import androidx.compose.foundation.layout.A0;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.B;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.foundation.layout.E0;
import androidx.compose.foundation.layout.G0;
import androidx.compose.foundation.layout.HorizontalAlignElement;
import androidx.compose.foundation.layout.K0;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.foundation.lazy.D;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.snapshots.t;
import androidx.compose.ui.n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.N;
import androidx.compose.ui.q;
import androidx.navigation.compose.p;
import com.comscore.streaming.AdvertisementType;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3137f0;
import com.google.android.gms.internal.mlkit_vision_barcode.M5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3586b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W4;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.assembly.compose.buttons.C4079d;
import com.quizlet.assembly.compose.buttons.C4097w;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.features.flashcards.C4237k;
import com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r;
import com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.y;
import com.quizlet.quizletandroid.R;
import com.quizlet.themes.m;
import com.quizlet.themes.w;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.InterfaceC4938g;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class k {
    public static final a0 a;
    public static final b0 b;

    static {
        com.quizlet.themes.a aVar = com.quizlet.themes.a.c;
        a = V.c(AbstractC0240f.r(200, 0, aVar.a(), 2), 2).a(V.g(AbstractC0240f.r(200, 0, aVar.a(), 2), new C4237k(6))).a(V.b(AbstractC0240f.r(200, 0, aVar.a(), 2), 14));
        b = V.d(AbstractC0240f.r(200, 0, aVar.b(), 2), 2).a(V.i(AbstractC0240f.r(200, 0, aVar.b(), 2), new C4237k(6))).a(V.f(AbstractC0240f.r(200, 0, aVar.b(), 2), 14));
    }

    public static final void a(com.quizlet.features.infra.folder.menu.screenstates.d state, q qVar, Function1 function1, Function2 function2, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(state, "state");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1331477678);
        int i2 = i | (c0814p.f(state) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | (c0814p.h(function2) ? 2048 : 1024) | (c0814p.h(function0) ? 16384 : 8192);
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            B bA = A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
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
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            d(state.a(), state.b(), new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, false), null, function1, function2, c0814p, (i2 << 6) & 516096);
            E.f((state instanceof com.quizlet.features.infra.folder.menu.screenstates.c) && ((com.quizlet.features.infra.folder.menu.screenstates.c) state).c, null, a, b, null, androidx.compose.runtime.internal.e.e(-931972064, new com.quizlet.features.infra.folder.create.coursefolder.composable.k(1, function0), c0814p), c0814p, 1600518, 18);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new r(state, qVar, function1, function2, function0, i);
        }
    }

    public static final void b(com.quizlet.features.infra.folder.menu.screenstates.d state, q qVar, Function1 function1, Function2 function2, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(state, "state");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(673085630);
        int i2 = i | (c0814p.f(state) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | (c0814p.h(function2) ? 2048 : 1024) | (c0814p.h(function0) ? 16384 : 8192) | (c0814p.h(function02) ? 131072 : 65536);
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            B bA = A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
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
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, bA, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            Q4.b(AbstractC3106b5.d(c0814p, R.string.save_to_folder_title), K0.c(n.b, 1.0f), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(w.a)).d, c0814p, 48, 0, 65528);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException("invalid weight 1.0; must be greater than zero".toString());
            }
            d(state.a(), state.b(), new LayoutWeightElement(1.0f, false), null, function1, function2, c0814p, (i2 << 6) & 516096);
            HorizontalAlignElement horizontalAlignElement = new HorizontalAlignElement(androidx.compose.ui.b.o);
            m mVar = m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            q qVarY = AbstractC0382e.y(horizontalAlignElement, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            mVar.s();
            G0 g0B = E0.b(AbstractC0398m.g(f), androidx.compose.ui.b.j, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarY);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            AbstractC3586b5.a(AbstractC3106b5.d(c0814p, R.string.cancel), null, function02, false, C4076a.m, C4097w.a, null, null, null, c0814p, (i2 >> 9) & 896, 970);
            String strD = AbstractC3106b5.d(c0814p, R.string.save);
            com.quizlet.features.infra.folder.menu.screenstates.c cVar = state instanceof com.quizlet.features.infra.folder.menu.screenstates.c ? (com.quizlet.features.infra.folder.menu.screenstates.c) state : null;
            W4.a(strD, null, function0, cVar != null ? cVar.c : false, null, com.quizlet.assembly.compose.buttons.r.a, null, null, null, false, c0814p, (i2 >> 6) & 896, 978);
            c0814p = c0814p;
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.e((Object) state, (Object) qVar, function1, (InterfaceC4938g) function2, function0, (Object) function02, i, 3);
        }
    }

    public static final void c(x modalState, com.quizlet.features.infra.folder.menu.screenstates.d state, q qVar, Function1 function1, Function2 function2, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        q qVar2;
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        Intrinsics.checkNotNullParameter(state, "state");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(512474332);
        int i2 = i | (c0814p.h(modalState) ? 4 : 2) | (c0814p.f(state) ? 32 : 16) | 384 | (c0814p.h(function1) ? 2048 : 1024) | (c0814p.h(function2) ? 16384 : 8192) | (c0814p.h(function0) ? 131072 : 65536) | (c0814p.h(function02) ? 1048576 : 524288);
        if ((599187 & i2) == 599186 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            n nVar = n.b;
            androidx.compose.runtime.V v = C0804k.a;
            c0814p.X(825942060);
            Object objI = c0814p.I();
            if (objI == v) {
                objI = new y(function1, modalState, 2);
                c0814p.i0(objI);
            }
            Function1 function12 = (Function1) objI;
            c0814p.p(false);
            U5.a(modalState, androidx.compose.runtime.internal.e.e(1389309350, new com.quizlet.assembly.compose.buttons.A(state, function12, function2, function0, 12), c0814p), N.G(nVar, "AddToFolderSubfolderMenu"), androidx.compose.runtime.internal.e.e(-1924907164, new p(state, function12, function2, function0, function02, 1), c0814p), null, null, null, false, function02, c0814p, (i2 & 14) | 3128 | ((i2 << 6) & 234881024), 240);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4079d(modalState, state, qVar2, function1, function2, function0, function02, i, 3);
        }
    }

    public static final void d(kotlinx.collections.immutable.b items, kotlinx.collections.immutable.c selectedItems, q qVar, A0 a0, Function1 function1, Function2 function2, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function1 function12;
        Function2 function22;
        int i3;
        A0 a0E;
        C0814p c0814p;
        A0 a02;
        Intrinsics.checkNotNullParameter(items, "items");
        Intrinsics.checkNotNullParameter(selectedItems, "selectedItems");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(2040246669);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p2.f(items) : c0814p2.h(items) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(selectedItems) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.f(qVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= 1024;
        }
        if ((i & 24576) == 0) {
            function12 = function1;
            i2 |= c0814p2.h(function12) ? 16384 : 8192;
        } else {
            function12 = function1;
        }
        if ((196608 & i) == 0) {
            function22 = function2;
            i2 |= c0814p2.h(function22) ? 131072 : 65536;
        } else {
            function22 = function2;
        }
        if ((74899 & i2) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            a02 = a0;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            int i4 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i4 == 0 || c0814p2.w()) {
                m mVar = m.g;
                mVar.q();
                float f = com.quizlet.ui.resources.designsystem.generated.j.i;
                mVar.p();
                i3 = i2 & (-7169);
                a0E = AbstractC0382e.e(DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.j, 5);
            } else {
                c0814p2.Q();
                i3 = i2 & (-7169);
                a0E = a0;
            }
            c0814p2.q();
            c0814p2.X(-1074542306);
            Object objI = c0814p2.I();
            if (objI == v) {
                objI = new t();
                c0814p2.i0(objI);
            }
            t tVar = (t) objI;
            c0814p2.p(false);
            androidx.compose.foundation.lazy.A a2 = D.a(0, c0814p2, 3);
            q qVarD = M5.d(qVar, a2);
            C0380d c0380d = AbstractC0398m.a;
            m.g.n();
            C0392j c0392jG = AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.o);
            c0814p2.X(-1074529567);
            boolean z = ((i3 & 14) == 4 || ((i3 & 8) != 0 && c0814p2.h(items))) | ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((458752 & i3) == 131072) | ((i3 & 57344) == 16384);
            Object objI2 = c0814p2.I();
            if (z || objI2 == v) {
                androidx.navigation.internal.i iVar = new androidx.navigation.internal.i(items, selectedItems, tVar, function22, function12, 2);
                c0814p2.i0(iVar);
                objI2 = iVar;
            }
            c0814p2.p(false);
            A0 a03 = a0E;
            c0814p = c0814p2;
            AbstractC3137f0.a(qVarD, a2, a03, c0392jG, null, null, false, (Function1) objI2, c0814p, 0, AdvertisementType.BRANDED_ON_DEMAND_MID_ROLL);
            a02 = a03;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.screens.a(items, selectedItems, qVar, a02, function1, function2, i);
        }
    }
}
