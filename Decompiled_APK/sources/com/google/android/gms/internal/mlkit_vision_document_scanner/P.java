package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
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
import androidx.compose.runtime.C0839z;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.facebook.FacebookException;
import com.facebook.internal.C1553h;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTGppKeys;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.achievements.ui.composables.C4215b;
import com.quizlet.features.flashcards.C4235i;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import java.util.WeakHashMap;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class P {
    public static final void a(com.quizlet.login.login.data.w wVar, Function0 function0, Function0 function02, Function0 function03, Function2 function2, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function04;
        Function0 function05;
        com.quizlet.login.authentication.k kVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1382624678);
        int i2 = i | (c0814p.f(wVar) ? 4 : 2) | (c0814p.h(function0) ? 32 : 16) | (c0814p.h(function02) ? 256 : 128) | (c0814p.h(function03) ? 2048 : 1024) | (c0814p.h(function2) ? 16384 : 8192) | (c0814p.f(qVar) ? 131072 : 65536);
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
            function05 = function02;
            function04 = function0;
        } else {
            c0814p.U(681016263, wVar.e);
            Object[] objArr = new Object[0];
            c0814p.X(681017439);
            boolean z = (i2 & 14) == 4;
            Object objI = c0814p.I();
            Object obj = C0804k.a;
            if (z || objI == obj) {
                objI = new com.quizlet.featuregate.growthbook.a(wVar, 29);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p, 0, 6);
            c0814p.p(false);
            Object[] objArr2 = new Object[0];
            c0814p.X(681019764);
            Object objI2 = c0814p.I();
            if (objI2 == obj) {
                objI2 = new com.quizlet.features.settings.composables.changeusername.c(26);
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
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            androidx.compose.ui.q qVarU = AbstractC0460p.u(androidx.compose.foundation.layout.K0.q(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.x0, 1).g(fillElement), AbstractC0460p.r(c0814p), false, 14);
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarW = AbstractC0382e.w(qVarU, f, DefinitionKt.NO_Float_VALUE, 2);
            mVar.s();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarW, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7);
            androidx.compose.foundation.layout.B bA2 = androidx.compose.foundation.layout.A.a(c0384f, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarY);
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
            Context context = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
            Intrinsics.checkNotNullParameter(context, "context");
            String strA = (wVar.b || (kVar = wVar.a) == null) ? null : kVar.a(context);
            mVar.s();
            E.a(strA, androidx.compose.foundation.layout.K0.c(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 1.0f), c0814p, 0);
            String str = (String) interfaceC0773a0.getValue();
            mVar.s();
            androidx.compose.ui.q qVarY2 = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            c0814p.X(-851134006);
            boolean zF = c0814p.f(interfaceC0773a0);
            Object objI3 = c0814p.I();
            if (zF || objI3 == obj) {
                objI3 = new com.quizlet.assembly.compose.modals.t(interfaceC0773a0, 24);
                c0814p.i0(objI3);
            }
            Function1 function1 = (Function1) objI3;
            boolean zR = AbstractC4178x.r(c0814p, false, -851127702, interfaceC0773a0);
            Object objI4 = c0814p.I();
            if (zR || objI4 == obj) {
                objI4 = new com.quizlet.features.practicetest.detail.composables.f(interfaceC0773a0, 18);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            D.a(R.string.login_email_label, 0, 16, c0814p, qVarY2, str, null, (Function0) objI4, function1);
            String str2 = (String) interfaceC0773a02.getValue();
            mVar.s();
            androidx.compose.ui.q qVarY3 = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            c0814p.X(-851123795);
            boolean zF2 = c0814p.f(interfaceC0773a02);
            Object objI5 = c0814p.I();
            if (zF2 || objI5 == obj) {
                objI5 = new com.quizlet.assembly.compose.modals.t(interfaceC0773a02, 25);
                c0814p.i0(objI5);
            }
            Function1 function12 = (Function1) objI5;
            boolean zR2 = AbstractC4178x.r(c0814p, false, -851119539, interfaceC0773a02);
            Object objI6 = c0814p.I();
            if (zR2 || objI6 == obj) {
                objI6 = new com.quizlet.features.practicetest.detail.composables.f(interfaceC0773a02, 19);
                c0814p.i0(objI6);
            }
            Function0 function06 = (Function0) objI6;
            c0814p.p(false);
            c0814p.X(-851122075);
            int i5 = i2 & 57344;
            boolean zF3 = (i5 == 16384) | c0814p.f(interfaceC0773a0) | c0814p.f(interfaceC0773a02);
            Object objI7 = c0814p.I();
            if (zF3 || objI7 == obj) {
                objI7 = new com.quizlet.features.questiontypes.written.ui.c(function2, interfaceC0773a0, interfaceC0773a02, 1);
                c0814p.i0(objI7);
            }
            c0814p.p(false);
            I.a(str2, function12, qVarY3, function06, (Function0) objI7, c0814p, 0);
            c0814p = c0814p;
            boolean z2 = (StringsKt.O((String) interfaceC0773a0.getValue()) || StringsKt.O((String) interfaceC0773a02.getValue())) ? false : true;
            mVar.s();
            androidx.compose.ui.q qVarY4 = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            c0814p.X(-851111003);
            boolean zF4 = c0814p.f(interfaceC0773a0) | (i5 == 16384) | c0814p.f(interfaceC0773a02);
            Object objI8 = c0814p.I();
            if (zF4 || objI8 == obj) {
                objI8 = new com.quizlet.features.questiontypes.written.ui.c(function2, interfaceC0773a0, interfaceC0773a02, 2);
                c0814p.i0(objI8);
            }
            c0814p.p(false);
            c(0, c0814p, qVarY4, (Function0) objI8, z2);
            mVar.s();
            b((i2 >> 9) & 14, c0814p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), function03);
            function04 = function0;
            function05 = function02;
            f((i2 & ContentType.LONG_FORM_ON_DEMAND) | 6 | (i2 & 896), c0814p, function04, function05, wVar.d);
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.e(wVar, function04, function05, function03, function2, qVar, i);
        }
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        int i2;
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2065642447);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            function02 = function0;
        } else {
            function02 = function0;
            AbstractC3586b5.a(AbstractC3106b5.d(c0814p, R.string.login_forgot_password), androidx.compose.foundation.layout.K0.c(qVar, 1.0f), function02, false, null, com.quizlet.login.common.util.c.a(c0814p), null, null, null, c0814p, (i2 << 6) & 896, 984);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.buttons.U(function02, qVar, i, 6);
        }
    }

    public static final void c(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0, boolean z) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1913520796);
        int i2 = i | (c0814p.h(function0) ? 4 : 2) | (c0814p.g(z) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            W4.a(AbstractC3106b5.d(c0814p, R.string.login_label), androidx.compose.foundation.layout.K0.c(qVar, 1.0f), function0, z, null, com.quizlet.login.common.util.c.a(c0814p), null, null, null, false, c0814p, (i2 << 6) & 8064, 976);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4215b(function0, z, qVar, i, 2);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void d(Function0 navigateBack, Function0 navigateToForgotPassword, Function0 navigateToHome, Function0 navigateToUpsell, Function0 navigateToMagicLinkConfirmation, Function0 navigateToEmailConfirmation, Function2 navigateToPromptForBirthday, Function1 navigateToMultipleAccountsFound, com.quizlet.login.login.viewmodel.a aVar, com.quizlet.features.infra.google.e eVar, com.quizlet.data.interactor.achievements.f fVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        final com.quizlet.login.login.viewmodel.a aVar2;
        int i2;
        com.quizlet.data.interactor.achievements.f fVarD;
        com.quizlet.features.infra.google.e eVar2;
        boolean z;
        com.quizlet.data.interactor.achievements.f fVar2;
        boolean z2;
        com.quizlet.data.interactor.achievements.f fVar3;
        com.quizlet.login.login.viewmodel.a aVar3;
        com.quizlet.features.infra.google.e eVar3;
        kotlinx.coroutines.flow.d0 d0Var;
        androidx.compose.runtime.V v;
        com.quizlet.login.login.viewmodel.a aVar4;
        com.quizlet.data.interactor.achievements.f fVar4;
        com.quizlet.features.infra.google.e eVar4;
        Intrinsics.checkNotNullParameter(navigateBack, "navigateBack");
        Intrinsics.checkNotNullParameter(navigateToForgotPassword, "navigateToForgotPassword");
        Intrinsics.checkNotNullParameter(navigateToHome, "navigateToHome");
        Intrinsics.checkNotNullParameter(navigateToUpsell, "navigateToUpsell");
        Intrinsics.checkNotNullParameter(navigateToMagicLinkConfirmation, "navigateToMagicLinkConfirmation");
        Intrinsics.checkNotNullParameter(navigateToEmailConfirmation, "navigateToEmailConfirmation");
        Intrinsics.checkNotNullParameter(navigateToPromptForBirthday, "navigateToPromptForBirthday");
        Intrinsics.checkNotNullParameter(navigateToMultipleAccountsFound, "navigateToMultipleAccountsFound");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1332026117);
        int i3 = i | (c0814p2.h(navigateBack) ? 4 : 2) | (c0814p2.h(navigateToForgotPassword) ? 32 : 16) | (c0814p2.h(navigateToHome) ? 256 : 128) | (c0814p2.h(navigateToUpsell) ? 2048 : 1024) | (c0814p2.h(navigateToMagicLinkConfirmation) ? 16384 : 8192) | (c0814p2.h(navigateToEmailConfirmation) ? 131072 : 65536) | (c0814p2.h(navigateToPromptForBirthday) ? 1048576 : 524288) | (c0814p2.h(navigateToMultipleAccountsFound) ? 8388608 : 4194304) | 301989888;
        if ((306783379 & i3) == 306783378 && c0814p2.x()) {
            c0814p2.Q();
            eVar4 = eVar;
            fVar4 = fVar;
            c0814p = c0814p2;
            aVar4 = aVar;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                c0814p2.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p2);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p2);
                c0814p2.Y(1729797275);
                androidx.lifecycle.w0 w0VarE = AbstractC3417z1.e(com.quizlet.login.login.viewmodel.f.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p2);
                c0814p = c0814p2;
                c0814p.p(false);
                c0814p.p(false);
                aVar2 = (com.quizlet.login.login.viewmodel.a) w0VarE;
                c0814p.X(1907377511);
                androidx.compose.runtime.X0 x0 = AndroidCompositionLocals_androidKt.b;
                Object objB = com.google.android.gms.internal.mlkit_vision_barcode.K6.b(com.quizlet.login.di.a.class, c0814p.j(x0));
                c0814p.p(false);
                com.quizlet.features.infra.google.e eVar5 = (com.quizlet.features.infra.google.e) ((C4622e) ((com.quizlet.login.di.a) objB)).B.get();
                i2 = i3 & (-2113929217);
                c0814p.X(1907377511);
                Object objB2 = com.google.android.gms.internal.mlkit_vision_barcode.K6.b(com.quizlet.login.di.a.class, c0814p.j(x0));
                c0814p.p(false);
                fVarD = ((C4622e) ((com.quizlet.login.di.a) objB2)).b.D();
                eVar2 = eVar5;
            } else {
                c0814p2.Q();
                i2 = i3 & (-2113929217);
                aVar2 = aVar;
                eVar2 = eVar;
                fVarD = fVar;
                c0814p = c0814p2;
            }
            c0814p.q();
            Object objI = c0814p.I();
            androidx.compose.runtime.V v2 = C0804k.a;
            if (objI == v2) {
                objI = android.support.v4.media.session.a.c(C0776c.n(kotlin.coroutines.n.a, c0814p), c0814p);
            }
            kotlinx.coroutines.C c = ((C0839z) objI).a;
            c0814p.X(-1034426934);
            Object objI2 = c0814p.I();
            if (objI2 == v2) {
                objI2 = C0776c.z(null);
                c0814p.i0(objI2);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI2;
            Object objG = com.google.android.gms.measurement.internal.Z.g(-1034424295, c0814p, false);
            if (objG == v2) {
                objG = C0776c.z(new com.quizlet.features.settings.composables.changeusername.c(24));
                c0814p.i0(objG);
            }
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objG;
            c0814p.p(false);
            com.facebook.login.B b = (com.facebook.login.B) interfaceC0773a0.getValue();
            c0814p.X(-1034421893);
            boolean zH = c0814p.h(fVarD);
            Object objI3 = c0814p.I();
            if (zH || objI3 == v2) {
                objI3 = new com.quizlet.login.login.ui.d(fVarD, interfaceC0773a0, null);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            C0776c.f(c0814p, b, (Function2) objI3);
            com.facebook.login.B facebookLoginManager = (com.facebook.login.B) interfaceC0773a0.getValue();
            c0814p.X(-1034418675);
            if (facebookLoginManager == null) {
                fVar2 = fVarD;
                z2 = false;
            } else {
                c0814p.X(-298007855);
                boolean zH2 = c0814p.h(aVar2);
                Object objI4 = c0814p.I();
                if (zH2 || objI4 == v2) {
                    z = false;
                    final Object[] objArr = 0 == true ? 1 : 0;
                    objI4 = new Function1() { // from class: com.quizlet.login.login.ui.a
                        @Override // kotlin.jvm.functions.Function1
                        public final Object invoke(Object obj) {
                            switch (objArr) {
                                case 0:
                                    String it2 = (String) obj;
                                    Intrinsics.checkNotNullParameter(it2, "it");
                                    ((com.quizlet.login.login.viewmodel.f) aVar2).E(new com.quizlet.login.login.data.g(it2));
                                    break;
                                default:
                                    FacebookException it3 = (FacebookException) obj;
                                    Intrinsics.checkNotNullParameter(it3, "it");
                                    ((com.quizlet.login.login.viewmodel.f) aVar2).E(new com.quizlet.login.login.data.h(it3));
                                    break;
                            }
                            return Unit.a;
                        }
                    };
                    c0814p.i0(objI4);
                } else {
                    z = false;
                }
                Function1 onSuccess = (Function1) objI4;
                c0814p.p(z);
                c0814p.X(-298005290);
                boolean zH3 = c0814p.h(aVar2);
                Object objI5 = c0814p.I();
                if (zH3 || objI5 == v2) {
                    final int i4 = 1;
                    objI5 = new Function1() { // from class: com.quizlet.login.login.ui.a
                        @Override // kotlin.jvm.functions.Function1
                        public final Object invoke(Object obj) {
                            switch (i4) {
                                case 0:
                                    String it2 = (String) obj;
                                    Intrinsics.checkNotNullParameter(it2, "it");
                                    ((com.quizlet.login.login.viewmodel.f) aVar2).E(new com.quizlet.login.login.data.g(it2));
                                    break;
                                default:
                                    FacebookException it3 = (FacebookException) obj;
                                    Intrinsics.checkNotNullParameter(it3, "it");
                                    ((com.quizlet.login.login.viewmodel.f) aVar2).E(new com.quizlet.login.login.data.h(it3));
                                    break;
                            }
                            return Unit.a;
                        }
                    };
                    c0814p.i0(objI5);
                }
                Function1 onError = (Function1) objI5;
                c0814p.p(false);
                List list = com.quizlet.facebook.compose.b.a;
                Intrinsics.checkNotNullParameter(facebookLoginManager, "facebookLoginManager");
                Intrinsics.checkNotNullParameter(onSuccess, "onSuccess");
                Intrinsics.checkNotNullParameter(onError, "onError");
                c0814p.X(455584272);
                c0814p.X(-585305935);
                Object objI6 = c0814p.I();
                if (objI6 == v2) {
                    objI6 = new C1553h();
                    c0814p.i0(objI6);
                }
                com.facebook.j jVar = (com.facebook.j) objI6;
                fVar2 = fVarD;
                c0814p.p(false);
                com.facebook.login.y yVar = com.facebook.login.B.b;
                com.facebook.login.z zVar = new com.facebook.login.z(facebookLoginManager, jVar);
                c0814p.X(-585299023);
                boolean zH4 = c0814p.h(jVar);
                Object objI7 = c0814p.I();
                if (zH4 || objI7 == v2) {
                    objI7 = new androidx.navigation.U(jVar, 25);
                    c0814p.i0(objI7);
                }
                c0814p.p(false);
                androidx.activity.compose.o oVarF = androidx.work.P.f(zVar, (Function1) objI7, c0814p);
                c0814p.X(-585293651);
                boolean zH5 = c0814p.h(facebookLoginManager) | c0814p.h(jVar) | c0814p.f(onSuccess) | c0814p.f(onError);
                Object objI8 = c0814p.I();
                if (zH5 || objI8 == v2) {
                    objI8 = new androidx.navigation.internal.e(facebookLoginManager, jVar, onSuccess, onError, 3);
                    c0814p.i0(objI8);
                }
                z2 = false;
                c0814p.p(false);
                C0776c.c(onSuccess, onError, (Function1) objI8, c0814p);
                c0814p.X(-585274038);
                Object objI9 = c0814p.I();
                if (objI9 == v2) {
                    objI9 = new com.quizlet.facebook.compose.a(oVarF, 0);
                    c0814p.i0(objI9);
                }
                c0814p.p(false);
                c0814p.p(false);
                interfaceC0773a02.setValue((Function0) objI9);
                Unit unit = Unit.a;
            }
            Object objG2 = com.google.android.gms.measurement.internal.Z.g(-1034407659, c0814p, z2);
            if (objG2 == v2) {
                objG2 = new androidx.work.impl.utils.q(c, eVar2, aVar2, 28);
                c0814p.i0(objG2);
            }
            Function0 function0 = (Function0) objG2;
            c0814p.p(z2);
            com.quizlet.login.login.viewmodel.f fVar5 = (com.quizlet.login.login.viewmodel.f) aVar2;
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(fVar5.h, c0814p);
            kotlinx.coroutines.flow.d0 d0Var2 = fVar5.i;
            c0814p.X(-1034391415);
            boolean z3 = ((i2 & 14) == 4) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i2 & 896) == 256) | ((i2 & 7168) == 2048) | ((57344 & i2) == 16384) | ((458752 & i2) == 131072) | ((3670016 & i2) == 1048576) | ((29360128 & i2) == 8388608);
            Object objI10 = c0814p.I();
            if (z3 || objI10 == v2) {
                fVar3 = fVar2;
                aVar3 = aVar2;
                eVar3 = eVar2;
                d0Var = d0Var2;
                v = v2;
                com.quizlet.login.login.ui.e eVar6 = new com.quizlet.login.login.ui.e(navigateBack, navigateToForgotPassword, function0, navigateToHome, navigateToUpsell, navigateToMagicLinkConfirmation, navigateToEmailConfirmation, navigateToPromptForBirthday, navigateToMultipleAccountsFound, interfaceC0773a02, null);
                c0814p.i0(eVar6);
                objI10 = eVar6;
            } else {
                fVar3 = fVar2;
                aVar3 = aVar2;
                eVar3 = eVar2;
                d0Var = d0Var2;
                v = v2;
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b2 = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI10, c0814p);
            Unit unit2 = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b2) | c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI11 = c0814p.I();
            if (zF || objI11 == v) {
                objI11 = new com.quizlet.login.login.ui.c(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI11);
            }
            c0814p.p(false);
            com.quizlet.login.login.data.w wVar = (com.quizlet.login.login.data.w) AbstractC4178x.k(unit2, (Function2) objI11, c0814p, false, interfaceC0773a0G);
            c0814p.X(-1034364244);
            com.quizlet.login.login.viewmodel.a aVar5 = aVar3;
            boolean zH6 = c0814p.h(aVar5);
            Object objI12 = c0814p.I();
            if (zH6 || objI12 == v) {
                com.quizlet.login.common.navigation.d dVar = new com.quizlet.login.common.navigation.d(1, aVar5, com.quizlet.login.login.viewmodel.a.class, "onEvent", "onEvent(Lcom/quizlet/login/login/data/LoginEvent;)V", 0, 8);
                c0814p.i0(dVar);
                objI12 = dVar;
            }
            c0814p.p(false);
            e(wVar, null, (Function1) ((kotlin.reflect.f) objI12), c0814p, 0);
            aVar4 = aVar5;
            fVar4 = fVar3;
            eVar4 = eVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4235i(navigateBack, navigateToForgotPassword, navigateToHome, navigateToUpsell, navigateToMagicLinkConfirmation, navigateToEmailConfirmation, navigateToPromptForBirthday, navigateToMultipleAccountsFound, aVar4, eVar4, fVar4, i);
        }
    }

    public static final void e(com.quizlet.login.login.data.w wVar, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        Function1 function12;
        com.quizlet.login.login.data.w wVar2;
        androidx.compose.runtime.V v;
        int i2;
        int i3;
        C0814p c0814p;
        com.quizlet.login.authentication.k kVar;
        int i4 = 0;
        int i5 = 2;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-586305560);
        int i6 = i | (c0814p2.f(wVar) ? 4 : 2) | 48 | (c0814p2.h(function1) ? 256 : 128);
        if ((i6 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            qVar2 = qVar;
            function12 = function1;
            c0814p = c0814p2;
            wVar2 = wVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v2 = C0804k.a;
            float f = androidx.compose.material3.W4.a;
            com.quizlet.data.repository.achievements.h hVarA = androidx.compose.material3.W4.a(androidx.compose.material3.D.i(c0814p2), c0814p2, 14);
            androidx.compose.ui.platform.Q0 q0 = (androidx.compose.ui.platform.Q0) c0814p2.j(AbstractC0955m0.n);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, "login_screen");
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            qVar2 = nVar;
            AbstractC0725t3.a(qVarG, androidx.compose.runtime.internal.e.e(-699669596, new com.quizlet.login.login.ui.g(function1, hVarA, i4), c0814p2), null, null, null, 0, ((com.quizlet.themes.b) c0814p2.j(b)).b.g(), 0L, c0374a, androidx.compose.runtime.internal.e.e(1514435129, new com.quizlet.assembly.compose.menu.g((Object) hVarA, (Object) wVar, (InterfaceC4938g) function1, (Object) q0, 11), c0814p2), c0814p2, 805306416, 188);
            c0814p2.X(1563400183);
            if (wVar.c) {
                long jG = ((com.quizlet.themes.b) c0814p2.j(b)).b.g();
                c0814p = c0814p2;
                v = v2;
                i3 = i6;
                i2 = 256;
                wVar2 = wVar;
                function12 = function1;
                AbstractC3249r5.a(null, jG, c0814p, 0, 1);
            } else {
                function12 = function1;
                wVar2 = wVar;
                v = v2;
                i2 = 256;
                i3 = i6;
                c0814p = c0814p2;
            }
            c0814p.p(false);
            if (!wVar2.b || (kVar = wVar2.a) == null) {
                kVar = null;
            }
            if (kVar != null) {
                c0814p.X(211235920);
                int i7 = i3 & 896;
                boolean z = i7 == i2;
                Object objI = c0814p.I();
                if (z || objI == v) {
                    objI = new com.quizlet.login.intro.ui.k(i5, function12);
                    c0814p.i0(objI);
                }
                Function0 function0 = (Function0) objI;
                c0814p.p(false);
                c0814p.X(211238320);
                boolean z2 = i7 == i2;
                Object objI2 = c0814p.I();
                if (z2 || objI2 == v) {
                    objI2 = new com.quizlet.login.intro.ui.k(3, function12);
                    c0814p.i0(objI2);
                }
                c0814p.p(false);
                C0814p c0814p3 = c0814p;
                G.b(kVar, function0, (Function0) objI2, null, c0814p3, 0);
                c0814p = c0814p3;
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 22, qVar2, (Object) wVar2, (Object) function12);
        }
    }

    public static final void f(int i, InterfaceC0806l interfaceC0806l, Function0 function0, Function0 function02, boolean z) {
        int i2;
        Object obj = androidx.compose.foundation.layout.D.a;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-355678008);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(obj) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function02) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.g(z) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.X(-1644219718);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            androidx.compose.foundation.layout.S0 s0E = C0380d.e(c0814p);
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D(Boolean.valueOf(s0E.c.e().d > 0), c0814p);
            c0814p.p(false);
            Object[] objArr = new Object[0];
            c0814p.X(-653406671);
            Object objI = c0814p.I();
            Object obj2 = C0804k.a;
            if (objI == obj2) {
                objI = new com.quizlet.features.settings.composables.changeusername.c(25);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            Boolean bool = (Boolean) interfaceC0773a0D.getValue();
            bool.getClass();
            c0814p.X(-653404401);
            boolean zF = c0814p.f(interfaceC0773a0) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zF || objI2 == obj2) {
                objI2 = new com.quizlet.login.login.ui.h(interfaceC0773a0D, interfaceC0773a0, null);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.f(c0814p, bool, (Function2) objI2);
            if (((Boolean) interfaceC0773a0.getValue()).booleanValue()) {
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.C.a(nVar, 1.0f));
                AbstractC3626g5.b((i2 & ContentType.LONG_FORM_ON_DEMAND) | 6, c0814p, androidx.compose.foundation.layout.K0.c(nVar, 1.0f), function0);
                if (z) {
                    com.quizlet.themes.m.g.s();
                    AbstractC3594c5.a((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND, c0814p, androidx.compose.foundation.layout.K0.c(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 1.0f), function02);
                }
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.recyclerview.step.f(function0, function02, z, i);
        }
    }

    public static JSONArray g(JSONObject jSONObject) {
        JSONArray jSONArrayOptJSONArray = jSONObject.optJSONArray("Groups");
        return jSONArrayOptJSONArray != null ? jSONArrayOptJSONArray : new JSONArray();
    }

    public static void h(Context context, JSONObject jSONObject) {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        if (retrofit2.adapter.rxjava3.d.o(jSONObject) || !jSONObject.has(OTVendorListMode.GENERAL)) {
            return;
        }
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject(OTVendorListMode.GENERAL);
        if (retrofit2.adapter.rxjava3.d.o(jSONObjectOptJSONObject)) {
            return;
        }
        boolean zOptBoolean = jSONObjectOptJSONObject.optBoolean("useRTL");
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        sharedPreferences.edit().putBoolean("OT_USE_RTL", zOptBoolean).apply();
        OTLogger.c("OTTemplateUtils", 3, "saveUseRTLFlag: " + zOptBoolean);
    }

    public static void i(JSONArray jSONArray, SharedPreferences sharedPreferences) throws JSONException {
        JSONArray jSONArrayOptJSONArray;
        try {
            JSONObject jSONObject = new JSONObject();
            for (int i = 0; i < jSONArray.length(); i++) {
                jSONObject.put(jSONArray.optJSONObject(i).optString("CustomGroupId"), jSONArray.optJSONObject(i).optString("Type"));
                if (jSONArray.optJSONObject(i).has("SubGroups") && (jSONArrayOptJSONArray = jSONArray.optJSONObject(i).optJSONArray("SubGroups")) != null) {
                    for (int i2 = 0; i2 < jSONArrayOptJSONArray.length(); i2++) {
                        jSONObject.put(jSONArrayOptJSONArray.optJSONObject(i2).optString("CustomGroupId"), jSONArrayOptJSONArray.optJSONObject(i2).optString("Type"));
                    }
                }
            }
            OTLogger.c("OTTemplateUtils", 3, "Groups configured: " + jSONObject);
            sharedPreferences.edit().putString("OT_GROUP_ID_OBJECT", jSONObject.toString()).apply();
        } catch (JSONException e) {
            W.a("Error while saving groups in template,err: ", e, "OTTemplateUtils", 6);
        }
    }

    public static boolean j(Context context) {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
            z = false;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
        String string = defaultSharedPreferences.getString(OTGppKeys.IAB_GPP_TCFEU2_STRING, "");
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            string = defaultSharedPreferences.getString("IABTCF_TCString", "");
        }
        if (com.onetrust.otpublishers.headless.Internal.a.j(com.onetrust.otpublishers.headless.Internal.a.j(string) ? "" : string)) {
            return true;
        }
        return sharedPreferences.getBoolean("OT_SAVED_TC_STRING_TYPE_DEFAULT", false);
    }

    public static boolean k(Context context) {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
            z = false;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        return sharedPreferences.getBoolean("OT_USE_RTL", false);
    }
}
