package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0384f;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.foundation.layout.FillElement;
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
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.quizlet.assembly.compose.buttons.C4088m;
import com.quizlet.assembly.compose.buttons.C4090o;
import com.quizlet.assembly.compose.buttons.InterfaceC4092q;
import com.quizlet.assembly.compose.buttons.InterfaceC4099y;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.flashcards.C4236j;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.b0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3581b0 {
    public static final void a(com.quizlet.login.parentemail.data.o oVar, Function2 function2, Function0 function0, Function0 function02, Function1 function1, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1589205264);
        int i2 = i | (c0814p.f(oVar) ? 4 : 2) | (c0814p.h(function2) ? 32 : 16) | (c0814p.h(function0) ? 256 : 128) | (c0814p.h(function02) ? 2048 : 1024) | (c0814p.h(function1) ? 16384 : 8192) | (c0814p.f(qVar) ? 131072 : 65536);
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object[] objArr = new Object[0];
            c0814p.X(-389933621);
            Object objI = c0814p.I();
            Object obj = C0804k.a;
            if (objI == obj) {
                objI = new com.quizlet.features.settings.composables.changeusername.c(28);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            Object[] objArr2 = new Object[0];
            c0814p.X(-389931701);
            Object objI2 = c0814p.I();
            if (objI2 == obj) {
                objI2 = new com.quizlet.features.settings.composables.changeusername.c(29);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr2, null, (Function0) objI2, c0814p, 3072, 6);
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            FillElement fillElement = androidx.compose.foundation.layout.K0.c;
            androidx.compose.ui.q qVarG = qVar.g(fillElement);
            C0384f c0384f = AbstractC0398m.c;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0384f, gVar, c0814p, 48);
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
            c0814p.X(2117963601);
            Object objI3 = c0814p.I();
            if (objI3 == obj) {
                objI3 = new androidx.compose.ui.focus.p();
                c0814p.i0(objI3);
            }
            androidx.compose.ui.focus.p pVar = (androidx.compose.ui.focus.p) objI3;
            c0814p.p(false);
            Unit unit = Unit.a;
            c0814p.X(2117966057);
            Object objI4 = c0814p.I();
            if (objI4 == obj) {
                objI4 = new com.quizlet.login.parentemail.ui.a(pVar, null);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            C0776c.g(unit, pVar, (Function2) objI4, c0814p);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            androidx.compose.ui.q qVarU = AbstractC0460p.u(androidx.compose.foundation.layout.K0.q(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.x0, 1).g(fillElement), AbstractC0460p.r(c0814p), false, 14);
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarU2 = AbstractC0382e.u(qVarU, f);
            androidx.compose.foundation.layout.B bA2 = androidx.compose.foundation.layout.A.a(c0384f, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarU2);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA2, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            String strD = AbstractC3106b5.d(c0814p, R.string.parent_email_subtitle);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).o;
            long jF = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f();
            mVar.s();
            androidx.compose.material3.Q4.b(strD, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7), jF, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65528);
            com.quizlet.login.authentication.k kVar = oVar.b;
            c0814p.X(377653688);
            String strA = kVar == null ? null : kVar.a((Context) c0814p.j(AndroidCompositionLocals_androidKt.b));
            c0814p.p(false);
            mVar.u();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.g;
            mVar.s();
            E.a(strA, androidx.compose.foundation.layout.K0.c(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, f, 5), 1.0f), c0814p, 0);
            String str = (String) interfaceC0773a0.getValue();
            Integer numB = com.quizlet.login.common.util.c.b(oVar.c);
            c0814p.X(377675565);
            String strD2 = numB == null ? null : AbstractC3106b5.d(c0814p, numB.intValue());
            c0814p.p(false);
            androidx.compose.ui.q qVarK = androidx.compose.ui.focus.a.k(nVar, pVar);
            c0814p.X(377680548);
            boolean zF = c0814p.f(interfaceC0773a0) | ((i2 & 57344) == 16384);
            Object objI5 = c0814p.I();
            if (zF || objI5 == obj) {
                objI5 = new com.quizlet.features.flashcards.settings.ui.e(11, interfaceC0773a0, function1);
                c0814p.i0(objI5);
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarW = androidx.compose.ui.focus.a.w(qVarK, (Function1) objI5);
            c0814p.X(377666625);
            boolean zF2 = c0814p.f(interfaceC0773a0);
            Object objI6 = c0814p.I();
            if (zF2 || objI6 == obj) {
                objI6 = new com.quizlet.assembly.compose.modals.t(interfaceC0773a0, 27);
                c0814p.i0(objI6);
            }
            Function1 function12 = (Function1) objI6;
            boolean zR = AbstractC4178x.r(c0814p, false, 377668321, interfaceC0773a0);
            Object objI7 = c0814p.I();
            if (zR || objI7 == obj) {
                objI7 = new com.quizlet.features.practicetest.detail.composables.f(interfaceC0773a0, 20);
                c0814p.i0(objI7);
            }
            c0814p.p(false);
            D.a(R.string.parent_email_field_label, 0, 0, c0814p, qVarW, str, strD2, (Function0) objI7, function12);
            mVar.s();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            String str2 = (String) interfaceC0773a02.getValue();
            c0814p.X(377691396);
            boolean zF3 = c0814p.f(interfaceC0773a02);
            Object objI8 = c0814p.I();
            if (zF3 || objI8 == obj) {
                objI8 = new com.quizlet.assembly.compose.modals.t(interfaceC0773a02, 28);
                c0814p.i0(objI8);
            }
            Function1 function13 = (Function1) objI8;
            boolean zR2 = AbstractC4178x.r(c0814p, false, 377693188, interfaceC0773a02);
            Object objI9 = c0814p.I();
            if (zR2 || objI9 == obj) {
                objI9 = new com.quizlet.features.practicetest.detail.composables.f(interfaceC0773a02, 21);
                c0814p.i0(objI9);
            }
            Function0 function03 = (Function0) objI9;
            c0814p.p(false);
            c0814p.X(377694914);
            int i5 = i2 & ContentType.LONG_FORM_ON_DEMAND;
            boolean zF4 = (i5 == 32) | c0814p.f(interfaceC0773a0) | c0814p.f(interfaceC0773a02);
            Object objI10 = c0814p.I();
            if (zF4 || objI10 == obj) {
                objI10 = new com.quizlet.features.questiontypes.written.ui.c(function2, interfaceC0773a0, interfaceC0773a02, 4);
                c0814p.i0(objI10);
            }
            c0814p.p(false);
            I.a(str2, function13, qVarY, function03, (Function0) objI10, c0814p, 0);
            mVar.q();
            F.a((i2 >> 6) & 126, c0814p, AbstractC0382e.v(nVar, com.quizlet.themes.m.z0, com.quizlet.ui.resources.designsystem.generated.j.i), function0, function02);
            androidx.compose.ui.q qVarC3 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            String strD3 = AbstractC3106b5.d(c0814p, R.string.parent_email_create_account_button);
            InterfaceC4099y interfaceC4099yA = com.quizlet.login.common.util.c.a(c0814p);
            InterfaceC4092q c4088m = oVar.a ? new C4088m() : C4090o.a;
            boolean z = (StringsKt.O((String) interfaceC0773a0.getValue()) || StringsKt.O((String) interfaceC0773a02.getValue())) ? false : true;
            c0814p.X(377728322);
            boolean zF5 = (i5 == 32) | c0814p.f(interfaceC0773a0) | c0814p.f(interfaceC0773a02);
            Object objI11 = c0814p.I();
            if (zF5 || objI11 == obj) {
                objI11 = new com.quizlet.features.questiontypes.written.ui.c(function2, interfaceC0773a0, interfaceC0773a02, 3);
                c0814p.i0(objI11);
            }
            c0814p.p(false);
            W4.a(strD3, qVarC3, (Function0) objI11, z, null, interfaceC4099yA, c4088m, null, null, false, c0814p, 48, 912);
            c0814p = c0814p;
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.e(oVar, function2, function0, function02, function1, qVar, i);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r14v0 */
    /* JADX WARN: Type inference failed for: r14v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r14v2 */
    public static final void b(Function0 onNavigateBack, Function1 navigateToWebPage, Function0 navigateToEmailConfirmation, Function0 navigateToHome, Function1 navigateToMultipleAccountsFound, Function0 navigateToUpsell, Function0 navigateToMagicLinkConfirmation, com.quizlet.login.parentemail.viewmodel.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        ?? r14;
        int i2;
        com.quizlet.login.parentemail.viewmodel.a aVar2;
        com.quizlet.login.parentemail.viewmodel.a aVar3;
        com.quizlet.login.parentemail.viewmodel.a aVar4;
        Intrinsics.checkNotNullParameter(onNavigateBack, "onNavigateBack");
        Intrinsics.checkNotNullParameter(navigateToWebPage, "navigateToWebPage");
        Intrinsics.checkNotNullParameter(navigateToEmailConfirmation, "navigateToEmailConfirmation");
        Intrinsics.checkNotNullParameter(navigateToHome, "navigateToHome");
        Intrinsics.checkNotNullParameter(navigateToMultipleAccountsFound, "navigateToMultipleAccountsFound");
        Intrinsics.checkNotNullParameter(navigateToUpsell, "navigateToUpsell");
        Intrinsics.checkNotNullParameter(navigateToMagicLinkConfirmation, "navigateToMagicLinkConfirmation");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1804747265);
        int i3 = i | (c0814p.h(onNavigateBack) ? 4 : 2) | (c0814p.h(navigateToWebPage) ? 32 : 16) | (c0814p.h(navigateToEmailConfirmation) ? 256 : 128) | (c0814p.h(navigateToHome) ? 2048 : 1024) | (c0814p.h(navigateToMultipleAccountsFound) ? 16384 : 8192) | (c0814p.h(navigateToUpsell) ? 131072 : 65536) | (c0814p.h(navigateToMagicLinkConfirmation) ? 1048576 : 524288) | 4194304;
        if ((4793491 & i3) == 4793490 && c0814p.x()) {
            c0814p.Q();
            aVar4 = aVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                r14 = 0;
                Object objE = AbstractC3417z1.e(com.quizlet.login.parentemail.viewmodel.e.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                i2 = i3 & (-29360129);
                aVar2 = (com.quizlet.login.parentemail.viewmodel.a) objE;
            } else {
                c0814p.Q();
                i2 = i3 & (-29360129);
                r14 = 0;
                aVar2 = aVar;
            }
            c0814p.q();
            com.quizlet.login.parentemail.viewmodel.e eVar = (com.quizlet.login.parentemail.viewmodel.e) aVar2;
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(eVar.d, c0814p);
            kotlinx.coroutines.flow.d0 d0Var = eVar.e;
            c0814p.X(2110800290);
            boolean z = ((i2 & 3670016) == 1048576 ? true : r14) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32 ? true : r14) | ((i2 & 14) == 4 ? true : r14) | ((i2 & 896) == 256 ? true : r14) | ((i2 & 7168) == 2048 ? true : r14) | ((57344 & i2) == 16384 ? true : r14) | ((458752 & i2) == 131072 ? true : r14);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                com.quizlet.login.parentemail.ui.d dVar = new com.quizlet.login.parentemail.ui.d(navigateToWebPage, onNavigateBack, navigateToEmailConfirmation, navigateToHome, navigateToMultipleAccountsFound, navigateToUpsell, navigateToMagicLinkConfirmation, null);
                c0814p.i0(dVar);
                objI = dVar;
            }
            c0814p.p(r14);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zF || objI2 == v) {
                objI2 = new com.quizlet.login.parentemail.ui.c(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI2);
            }
            c0814p.p(r14);
            com.quizlet.login.parentemail.data.o oVar = (com.quizlet.login.parentemail.data.o) AbstractC4178x.k(unit, (Function2) objI2, c0814p, r14, interfaceC0773a0G);
            c0814p.X(2110821292);
            boolean zH = c0814p.h(aVar2);
            Object objI3 = c0814p.I();
            if (zH || objI3 == v) {
                aVar3 = aVar2;
                objI3 = new com.quizlet.login.common.navigation.d(1, aVar3, com.quizlet.login.parentemail.viewmodel.a.class, "onEvent", "onEvent(Lcom/quizlet/login/parentemail/data/ParentEmailEvent;)V", 0, 11);
                c0814p.i0(objI3);
            } else {
                aVar3 = aVar2;
            }
            c0814p.p(r14);
            c(oVar, (Function1) ((kotlin.reflect.f) objI3), c0814p, r14);
            aVar4 = aVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4236j(onNavigateBack, navigateToWebPage, navigateToEmailConfirmation, navigateToHome, navigateToMultipleAccountsFound, navigateToUpsell, navigateToMagicLinkConfirmation, aVar4, i);
        }
    }

    public static final void c(com.quizlet.login.parentemail.data.o oVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(212754446);
        if ((((c0814p.f(oVar) ? 4 : 2) | i | (c0814p.h(function1) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            float f = androidx.compose.material3.W4.a;
            com.quizlet.data.repository.achievements.h hVarA = androidx.compose.material3.W4.a(androidx.compose.material3.D.i(c0814p), c0814p, 14);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "parentEmailScreen");
            c0814p.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p).g, new C0416v0(C0380d.e(c0814p).k, AbstractC0382e.g));
            c0814p.p(false);
            AbstractC0725t3.a(qVarG, androidx.compose.runtime.internal.e.e(-1599561774, new com.quizlet.login.login.ui.g(function1, hVarA, 1), c0814p), null, null, null, 0, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), 0L, c0374a, androidx.compose.runtime.internal.e.e(-13719331, new com.quizlet.assembly.compose.input.h(hVarA, oVar, function1, 20), c0814p), c0814p, 805306422, 188);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(oVar, function1, i, 17);
        }
    }

    public static boolean d(Context context) {
        NetworkInfo activeNetworkInfo = ((ConnectivityManager) context.getSystemService("connectivity")).getActiveNetworkInfo();
        boolean z = activeNetworkInfo != null && activeNetworkInfo.isConnectedOrConnecting();
        OTLogger.c("NWUtils", 4, "isConnected = " + z);
        return z;
    }
}
