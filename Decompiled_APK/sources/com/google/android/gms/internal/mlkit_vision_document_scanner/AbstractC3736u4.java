package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.material3.AbstractC0725t3;
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
import androidx.compose.ui.platform.C0958o;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.HashMap;
import java.util.WeakHashMap;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.u4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3736u4 {
    public static final void a(com.quizlet.quizletandroid.ui.classcreation.i viewModel, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        com.quizlet.quizletandroid.ui.classcreation.i iVar;
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(985240096);
        if ((((c0814p2.h(viewModel) ? 4 : 2) | i) & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            iVar = viewModel;
            c0814p = c0814p2;
        } else {
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(viewModel.f, c0814p2);
            com.quizlet.quizletandroid.ui.classcreation.data.j jVar = (com.quizlet.quizletandroid.ui.classcreation.data.j) interfaceC0773a0M.getValue();
            if (jVar instanceof com.quizlet.quizletandroid.ui.classcreation.data.i) {
                c0814p2.X(566374549);
                c0814p = c0814p2;
                AbstractC3249r5.a(null, 0L, c0814p, 0, 3);
                c0814p.p(false);
                iVar = viewModel;
            } else {
                c0814p = c0814p2;
                if (!(jVar instanceof com.quizlet.quizletandroid.ui.classcreation.data.g) && !(jVar instanceof com.quizlet.quizletandroid.ui.classcreation.data.h) && !(jVar instanceof com.quizlet.quizletandroid.ui.classcreation.data.f)) {
                    throw com.google.android.gms.measurement.internal.Z.j(566373774, c0814p, false);
                }
                c0814p.X(377823336);
                c0814p.X(566378528);
                boolean zH = c0814p.h(viewModel);
                Object objI = c0814p.I();
                androidx.compose.runtime.V v = C0804k.a;
                if (zH || objI == v) {
                    C0958o c0958o = new C0958o(3, viewModel, com.quizlet.quizletandroid.ui.classcreation.i.class, "onSaveActionClicked", "onSaveActionClicked(Ljava/lang/String;Ljava/lang/String;Z)V", 0, 1);
                    c0814p.i0(c0958o);
                    objI = c0958o;
                }
                c0814p.p(false);
                kotlin.jvm.functions.c cVar = (kotlin.jvm.functions.c) ((kotlin.reflect.f) objI);
                c0814p.X(566380539);
                boolean zH2 = c0814p.h(viewModel);
                Object objI2 = c0814p.I();
                if (zH2 || objI2 == v) {
                    com.quizlet.learn.ads.g gVar = new com.quizlet.learn.ads.g(0, viewModel, com.quizlet.quizletandroid.ui.classcreation.i.class, "onNavigateBack", "onNavigateBack()V", 0, 27);
                    c0814p.i0(gVar);
                    objI2 = gVar;
                }
                c0814p.p(false);
                Function0 function0 = (Function0) ((kotlin.reflect.f) objI2);
                c0814p.X(566382691);
                boolean zH3 = c0814p.h(viewModel);
                Object objI3 = c0814p.I();
                if (zH3 || objI3 == v) {
                    com.quizlet.learn.ads.g gVar2 = new com.quizlet.learn.ads.g(0, viewModel, com.quizlet.quizletandroid.ui.classcreation.i.class, "onConfirmDialogClicked", "onConfirmDialogClicked()V", 0, 28);
                    iVar = viewModel;
                    c0814p.i0(gVar2);
                    objI3 = gVar2;
                } else {
                    iVar = viewModel;
                }
                c0814p.p(false);
                Function0 function02 = (Function0) ((kotlin.reflect.f) objI3);
                com.quizlet.quizletandroid.ui.classcreation.data.j jVar2 = (com.quizlet.quizletandroid.ui.classcreation.data.j) interfaceC0773a0M.getValue();
                com.quizlet.quizletandroid.ui.classcreation.data.b bVar = (jVar2 instanceof com.quizlet.quizletandroid.ui.classcreation.data.h ? (com.quizlet.quizletandroid.ui.classcreation.data.h) jVar2 : null) != null ? com.quizlet.quizletandroid.ui.classcreation.data.b.a : null;
                com.quizlet.quizletandroid.ui.classcreation.data.j jVar3 = (com.quizlet.quizletandroid.ui.classcreation.data.j) interfaceC0773a0M.getValue();
                d(cVar, function0, function02, bVar, (jVar3 instanceof com.quizlet.quizletandroid.ui.classcreation.data.f ? (com.quizlet.quizletandroid.ui.classcreation.data.f) jVar3 : null) != null ? com.quizlet.quizletandroid.ui.classcreation.data.a.a : null, c0814p, 0);
                c0814p.p(false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.a(iVar, i, 7);
        }
    }

    public static final void b(androidx.compose.foundation.layout.z0 z0Var, String str, String str2, boolean z, Function1 function1, Function1 function12, Function1 function13, com.quizlet.quizletandroid.ui.classcreation.data.b bVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-612910347);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(z0Var) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(str) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.f(str2) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.g(z) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.h(function1) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p2.h(function12) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p2.h(function13) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p2.f(bVar) ? 8388608 : 4194304;
        }
        if ((4793491 & i2) == 4793490 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.X(1539553397);
            Object objI = c0814p2.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = new androidx.compose.ui.focus.p();
                c0814p2.i0(objI);
            }
            androidx.compose.ui.focus.p pVar = (androidx.compose.ui.focus.p) objI;
            c0814p2.p(false);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            int i3 = i2;
            androidx.compose.ui.q qVarT = AbstractC0382e.t(AbstractC0460p.u(nVar, AbstractC0460p.r(c0814p2), false, 14), z0Var);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            androidx.compose.ui.q qVarG = AbstractC0382e.u(qVarT, com.quizlet.ui.resources.designsystem.generated.j.i).g(androidx.compose.foundation.layout.K0.c);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p2, 0);
            int i4 = c0814p2.P;
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
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p2, i4, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            c0814p2.X(196395491);
            String strD = bVar == null ? null : AbstractC3106b5.d(c0814p2, R.string.create_class_title_required);
            c0814p2.p(false);
            String strD2 = AbstractC3106b5.d(c0814p2, R.string.create_class_title_field_description);
            String strD3 = AbstractC3106b5.d(c0814p2, R.string.create_class_title_field_hint);
            c0814p2.X(196392801);
            Object objI2 = c0814p2.I();
            if (objI2 == v) {
                objI2 = new com.quizlet.login.magiclink.ui.e(pVar, 9);
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            int i5 = i3 >> 6;
            AbstractC3745v5.a(str, null, function1, strD2, strD3, 0, 0, null, null, 0, 0, (Function0) objI2, strD, false, false, null, 0, null, DefinitionKt.NO_Float_VALUE, null, null, null, c0814p2, ((i3 >> 3) & 14) | (i5 & 896), 384, 0, 8376290);
            c0814p = c0814p2;
            String strD4 = AbstractC3106b5.d(c0814p, R.string.create_class_description_field_description);
            String strD5 = AbstractC3106b5.d(c0814p, R.string.create_class_description_field_hint);
            mVar.s();
            int i6 = 817889280 | (i5 & 14);
            int i7 = i3 >> 9;
            AbstractC3745v5.a(str2, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), function12, strD4, strD5, 0, 5, null, pVar, 1, 0, null, null, false, false, null, 0, null, DefinitionKt.NO_Float_VALUE, null, null, null, c0814p, i6 | (i7 & 896), 6, 0, 8386912);
            e(z, function13, c0814p, (i7 & 14) | ((i3 >> 15) & ContentType.LONG_FORM_ON_DEMAND));
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.addtofolder.composables.c(z0Var, str, str2, z, function1, function12, function13, bVar, i);
        }
    }

    public static final void c(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.n nVar, com.quizlet.assembly.compose.modals.x popupState, Function0 onConfirmClick) {
        int i2;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(popupState, "popupState");
        Intrinsics.checkNotNullParameter(onConfirmClick, "onConfirmClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2033473277);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(popupState) : c0814p.h(popupState) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.d(R.string.create_class_offline_info_dialog_title) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.d(R.string.create_class_offline_info_dialog_description) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(onConfirmClick) ? 2048 : 1024;
        }
        int i3 = i2 | 24576;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            U5.b(popupState, nVar3, false, null, null, onConfirmClick, androidx.compose.runtime.internal.e.e(-785420760, new com.quizlet.features.questiontypes.fitb.ui.f(popupState, 2), c0814p), c0814p, (i3 & 14) | 1572872 | ((i3 >> 9) & ContentType.LONG_FORM_ON_DEMAND) | ((i3 << 6) & 458752), 28);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 17, popupState, onConfirmClick, nVar2);
        }
    }

    public static final void d(kotlin.jvm.functions.c cVar, Function0 function0, Function0 function02, com.quizlet.quizletandroid.ui.classcreation.data.b bVar, com.quizlet.quizletandroid.ui.classcreation.data.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        InterfaceC0773a0 interfaceC0773a0;
        int i2;
        InterfaceC0773a0 interfaceC0773a02;
        InterfaceC0773a0 interfaceC0773a03;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-444510134);
        int i3 = i | (c0814p.h(cVar) ? 4 : 2) | (c0814p.h(function0) ? 32 : 16) | (c0814p.h(function02) ? 256 : 128) | (c0814p.f(bVar) ? 2048 : 1024) | (c0814p.f(aVar) ? 16384 : 8192);
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            Object[] objArr = new Object[0];
            c0814p.X(-71611165);
            Object objI = c0814p.I();
            if (objI == v) {
                objI = new com.quizlet.login.resetpassword.ui.a(6);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a04 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            Object[] objArr2 = new Object[0];
            c0814p.X(-71609149);
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = new com.quizlet.login.resetpassword.ui.a(7);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a05 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr2, null, (Function0) objI2, c0814p, 3072, 6);
            Object[] objArr3 = new Object[0];
            c0814p.X(-71607195);
            Object objI3 = c0814p.I();
            if (objI3 == v) {
                objI3 = new com.quizlet.login.resetpassword.ui.a(8);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a06 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr3, null, (Function0) objI3, c0814p, 3072, 6);
            c0814p.X(-71605651);
            boolean zF = ((i3 & 14) == 4) | c0814p.f(interfaceC0773a04) | c0814p.f(interfaceC0773a05) | c0814p.f(interfaceC0773a06);
            Object objI4 = c0814p.I();
            if (zF || objI4 == v) {
                interfaceC0773a0 = interfaceC0773a05;
                i2 = i3;
                interfaceC0773a02 = interfaceC0773a04;
                interfaceC0773a03 = interfaceC0773a06;
                androidx.work.impl.utils.o oVar = new androidx.work.impl.utils.o(cVar, interfaceC0773a02, interfaceC0773a0, interfaceC0773a03, 10);
                c0814p.i0(oVar);
                objI4 = oVar;
            } else {
                interfaceC0773a0 = interfaceC0773a05;
                interfaceC0773a02 = interfaceC0773a04;
                i2 = i3;
                interfaceC0773a03 = interfaceC0773a06;
            }
            c0814p.p(false);
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(true, false, c0814p, 6, 6);
            long jG = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g();
            c0814p.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            int i4 = i2;
            C0374a c0374a = new C0374a(C0380d.e(c0814p).g, new C0416v0(C0380d.e(c0814p).k, AbstractC0382e.g));
            c0814p.p(false);
            AbstractC0725t3.a(null, androidx.compose.runtime.internal.e.e(1318809614, new com.quizlet.features.notes.upload.composables.upload.b(3, function0, (Function0) objI4), c0814p), null, null, null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(-1886150375, new com.quizlet.assembly.compose.menu.g(interfaceC0773a02, interfaceC0773a0, interfaceC0773a03, bVar), c0814p), c0814p, 805306416, 189);
            c0814p = c0814p;
            Unit unit = null;
            if (aVar != null) {
                com.quizlet.assembly.compose.modals.x.d(xVarH);
                c(8 | ((i4 << 3) & 7168), c0814p, null, xVarH, function02);
                unit = Unit.a;
            }
            if (unit == null) {
                xVarH.a();
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r((Object) cVar, (InterfaceC4938g) function0, (InterfaceC4938g) function02, (Object) bVar, (Object) aVar, i, 19);
        }
    }

    public static final void e(boolean z, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1768423836);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function1) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            C0380d c0380d = AbstractC0398m.a;
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(c0380d, hVar, c0814p, 48);
            int i3 = c0814p.P;
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
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, g0B, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true);
            androidx.compose.foundation.layout.G0 g0B2 = androidx.compose.foundation.layout.E0.b(c0380d, androidx.compose.ui.b.j, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, layoutWeightElement);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B2, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.create_class_permission_boolean_description), null, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).o, c0814p, 0, 0, 65534);
            c0814p.p(true);
            mVar.s();
            S4.a(z, AbstractC0382e.y(nVar, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), function1, false, c0814p, ((i2 << 3) & 896) | (i2 & 14), 8);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.essay.a(z, function1, i, 2);
        }
    }

    public static String f(HashMap map, String[] strArr) {
        StringBuilder sb = new StringBuilder();
        for (String str : strArr) {
            if (map.containsKey(str)) {
                sb.append((String) map.get(str));
            } else {
                K.c("encodeToBitString: field not found ", 6, str, "GPPHeader");
            }
        }
        return sb.toString();
    }
}
