package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0384f;
import androidx.compose.foundation.layout.C0392j;
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
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.achievements.ui.composables.C4215b;
import com.quizlet.features.flashcards.C4236j;
import com.quizlet.login.common.interactors.data.C4592c;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.g4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3625g4 {
    public static final void a(com.quizlet.login.signup.data.r rVar, final kotlin.jvm.functions.d dVar, Function0 function0, Function0 function02, Function0 function03, Function1 function1, Function1 function12, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        Function1 function13;
        boolean z;
        Function0 function04;
        Object obj;
        InterfaceC0773a0 interfaceC0773a0;
        Function0 function05;
        Function0 function06;
        final InterfaceC0773a0 interfaceC0773a02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1782686833);
        int i2 = i | (c0814p.f(rVar) ? 4 : 2) | (c0814p.h(dVar) ? 32 : 16) | (c0814p.h(function0) ? 256 : 128) | (c0814p.h(function02) ? 2048 : 1024) | (c0814p.h(function03) ? 16384 : 8192) | (c0814p.h(function1) ? 131072 : 65536) | (c0814p.h(function12) ? 1048576 : 524288) | (c0814p.f(qVar) ? 8388608 : 4194304);
        if ((i2 & 4793491) == 4793490 && c0814p.x()) {
            c0814p.Q();
            function05 = function0;
            function06 = function02;
            function04 = function03;
            function13 = function1;
        } else {
            Object[] objArr = new Object[0];
            c0814p.X(1251648113);
            Object objI = c0814p.I();
            Object obj2 = C0804k.a;
            if (objI == obj2) {
                objI = new com.quizlet.login.resetpassword.ui.a(1);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            final InterfaceC0773a0 interfaceC0773a03 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            Object[] objArr2 = new Object[0];
            c0814p.X(1251650033);
            Object objI2 = c0814p.I();
            if (objI2 == obj2) {
                objI2 = new com.quizlet.login.resetpassword.ui.a(2);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            final InterfaceC0773a0 interfaceC0773a04 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr2, null, (Function0) objI2, c0814p, 3072, 6);
            Object[] objArr3 = new Object[0];
            c0814p.X(1251652179);
            Object objI3 = c0814p.I();
            if (objI3 == obj2) {
                objI3 = new com.quizlet.login.resetpassword.ui.a(3);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            final InterfaceC0773a0 interfaceC0773a05 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr3, null, (Function0) objI3, c0814p, 3072, 6);
            Object[] objArr4 = new Object[0];
            c0814p.X(1251654195);
            Object objI4 = c0814p.I();
            if (objI4 == obj2) {
                objI4 = new com.quizlet.login.resetpassword.ui.a(4);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            final InterfaceC0773a0 interfaceC0773a06 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr4, null, (Function0) objI4, c0814p, 3072, 6);
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
            mVar.u();
            androidx.compose.ui.q qVarY2 = AbstractC0382e.y(qVarY, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            androidx.compose.foundation.layout.B bA2 = androidx.compose.foundation.layout.A.a(c0384f, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarY2);
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
            com.quizlet.login.authentication.k kVar = rVar.d;
            c0814p.X(1880190014);
            String strA = kVar == null ? null : kVar.a((Context) c0814p.j(AndroidCompositionLocals_androidKt.b));
            c0814p.p(false);
            mVar.s();
            E.a(strA, androidx.compose.foundation.layout.K0.c(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 1.0f), c0814p, 0);
            mVar.s();
            androidx.compose.ui.q qVarY3 = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            c0814p.X(1880199989);
            boolean zF = c0814p.f(interfaceC0773a05) | ((i2 & 3670016) == 1048576);
            Object objI5 = c0814p.I();
            if (zF || objI5 == obj2) {
                objI5 = new com.quizlet.features.flashcards.settings.ui.e(14, interfaceC0773a05, function12);
                c0814p.i0(objI5);
            }
            c0814p.p(false);
            C.a((Function1) objI5, rVar.b, qVarY3, null, c0814p, 0);
            String str = (String) interfaceC0773a03.getValue();
            int i5 = com.quizlet.login.common.util.c.b;
            com.quizlet.login.common.interactors.data.d dVar2 = rVar.f;
            Intrinsics.checkNotNullParameter(dVar2, "<this>");
            int i6 = Intrinsics.b(dVar2, C4592c.a) ? R.string.signup_parent_email_input_label : R.string.signup_email_input_label;
            Integer numB = com.quizlet.login.common.util.c.b(rVar.e);
            c0814p.X(1880216787);
            String strD = numB != null ? AbstractC3106b5.d(c0814p, numB.intValue()) : null;
            c0814p.p(false);
            mVar.s();
            androidx.compose.ui.q qVarY4 = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            c0814p.X(1880226826);
            boolean zF2 = ((i2 & 458752) == 131072) | c0814p.f(interfaceC0773a03);
            Object objI6 = c0814p.I();
            if (zF2 || objI6 == obj2) {
                function13 = function1;
                objI6 = new com.quizlet.features.flashcards.settings.ui.e(13, interfaceC0773a03, function13);
                c0814p.i0(objI6);
            } else {
                function13 = function1;
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarW2 = androidx.compose.ui.focus.a.w(qVarY4, (Function1) objI6);
            c0814p.X(1880208999);
            boolean zF3 = c0814p.f(interfaceC0773a03);
            Object objI7 = c0814p.I();
            if (zF3 || objI7 == obj2) {
                z = false;
                objI7 = new com.quizlet.login.signup.ui.a(interfaceC0773a03, 0);
                c0814p.i0(objI7);
            } else {
                z = false;
            }
            Function1 function14 = (Function1) objI7;
            boolean zR = AbstractC4178x.r(c0814p, z, 1880218939, interfaceC0773a03) | ((i2 & 57344) == 16384);
            Object objI8 = c0814p.I();
            if (zR || objI8 == obj2) {
                function04 = function03;
                objI8 = new com.quizlet.features.blocks.ui.c(function04, interfaceC0773a03, 13);
                c0814p.i0(objI8);
            } else {
                function04 = function03;
            }
            c0814p.p(false);
            D.a(i6, 0, 0, c0814p, qVarW2, str, strD, (Function0) objI8, function14);
            String str2 = (String) interfaceC0773a04.getValue();
            mVar.s();
            androidx.compose.ui.q qVarY5 = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            c0814p.X(1880234794);
            boolean zF4 = c0814p.f(interfaceC0773a04);
            Object objI9 = c0814p.I();
            if (zF4 || objI9 == obj2) {
                objI9 = new com.quizlet.login.signup.ui.a(interfaceC0773a04, 1);
                c0814p.i0(objI9);
            }
            Function1 function15 = (Function1) objI9;
            boolean zR2 = AbstractC4178x.r(c0814p, false, 1880241514, interfaceC0773a04);
            Object objI10 = c0814p.I();
            if (zR2 || objI10 == obj2) {
                objI10 = new com.quizlet.features.practicetest.detail.composables.f(interfaceC0773a04, 22);
                c0814p.i0(objI10);
            }
            Function0 function07 = (Function0) objI10;
            boolean zR3 = AbstractC4178x.r(c0814p, false, 1880236591, interfaceC0773a05);
            int i7 = i2 & ContentType.LONG_FORM_ON_DEMAND;
            boolean zF5 = zR3 | (i7 == 32) | c0814p.f(interfaceC0773a03) | c0814p.f(interfaceC0773a04) | c0814p.f(interfaceC0773a06);
            Object objI11 = c0814p.I();
            if (zF5 || objI11 == obj2) {
                final int i8 = 0;
                obj = new Function0() { // from class: com.quizlet.login.signup.ui.b
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i8) {
                            case 0:
                                Long l = (Long) interfaceC0773a05.getValue();
                                if (l != null) {
                                    Long lValueOf = Long.valueOf(l.longValue());
                                    String str3 = (String) interfaceC0773a03.getValue();
                                    String str4 = (String) interfaceC0773a04.getValue();
                                    Boolean bool = (Boolean) interfaceC0773a06.getValue();
                                    bool.booleanValue();
                                    dVar.invoke(lValueOf, str3, str4, bool);
                                }
                                break;
                            default:
                                Long l2 = (Long) interfaceC0773a05.getValue();
                                if (l2 != null) {
                                    Long lValueOf2 = Long.valueOf(l2.longValue());
                                    String str5 = (String) interfaceC0773a03.getValue();
                                    String str6 = (String) interfaceC0773a04.getValue();
                                    Boolean bool2 = (Boolean) interfaceC0773a06.getValue();
                                    bool2.booleanValue();
                                    dVar.invoke(lValueOf2, str5, str6, bool2);
                                }
                                break;
                        }
                        return Unit.a;
                    }
                };
                interfaceC0773a0 = interfaceC0773a06;
                c0814p.i0(obj);
            } else {
                obj = objI11;
                interfaceC0773a0 = interfaceC0773a06;
            }
            c0814p.p(false);
            I.a(str2, function15, qVarY5, function07, (Function0) obj, c0814p, 0);
            androidx.compose.animation.E.f(rVar.c, null, null, null, null, androidx.compose.runtime.internal.e.e(524210989, new com.quizlet.baseui.base.d(interfaceC0773a0, 13), c0814p), c0814p, 1572870, 30);
            c0814p = c0814p;
            mVar.q();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.i;
            function05 = function0;
            function06 = function02;
            F.a((i2 >> 6) & 126, c0814p, AbstractC0382e.w(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), com.quizlet.themes.m.y0, DefinitionKt.NO_Float_VALUE, 2), function05, function06);
            c0814p.X(1880270479);
            boolean zF6 = c0814p.f(interfaceC0773a05) | (i7 == 32) | c0814p.f(interfaceC0773a03) | c0814p.f(interfaceC0773a04) | c0814p.f(interfaceC0773a0);
            Object objI12 = c0814p.I();
            if (zF6 || objI12 == obj2) {
                final int i9 = 1;
                final InterfaceC0773a0 interfaceC0773a07 = interfaceC0773a0;
                interfaceC0773a02 = interfaceC0773a05;
                Function0 function08 = new Function0() { // from class: com.quizlet.login.signup.ui.b
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i9) {
                            case 0:
                                Long l = (Long) interfaceC0773a02.getValue();
                                if (l != null) {
                                    Long lValueOf = Long.valueOf(l.longValue());
                                    String str3 = (String) interfaceC0773a03.getValue();
                                    String str4 = (String) interfaceC0773a04.getValue();
                                    Boolean bool = (Boolean) interfaceC0773a07.getValue();
                                    bool.booleanValue();
                                    dVar.invoke(lValueOf, str3, str4, bool);
                                }
                                break;
                            default:
                                Long l2 = (Long) interfaceC0773a02.getValue();
                                if (l2 != null) {
                                    Long lValueOf2 = Long.valueOf(l2.longValue());
                                    String str5 = (String) interfaceC0773a03.getValue();
                                    String str6 = (String) interfaceC0773a04.getValue();
                                    Boolean bool2 = (Boolean) interfaceC0773a07.getValue();
                                    bool2.booleanValue();
                                    dVar.invoke(lValueOf2, str5, str6, bool2);
                                }
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p.i0(function08);
                objI12 = function08;
            } else {
                interfaceC0773a02 = interfaceC0773a05;
            }
            Function0 function09 = (Function0) objI12;
            c0814p.p(false);
            boolean z2 = (((Long) interfaceC0773a02.getValue()) == null || StringsKt.O((String) interfaceC0773a03.getValue()) || StringsKt.O((String) interfaceC0773a04.getValue())) ? false : true;
            mVar.q();
            b(0, c0814p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), function09, z2);
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4236j(rVar, dVar, function05, function06, function04, function13, function12, qVar, i);
        }
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0, boolean z) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1672931258);
        int i2 = i | (c0814p.h(function0) ? 4 : 2) | (c0814p.g(z) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            W4.a(AbstractC3106b5.d(c0814p, R.string.signup_button_text), androidx.compose.foundation.layout.K0.c(qVar, 1.0f), function0, z, null, com.quizlet.login.common.util.c.a(c0814p), null, null, null, false, c0814p, (i2 << 6) & 8064, 976);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4215b(function0, z, qVar, i, 3);
        }
    }

    public static final void c(com.quizlet.login.signup.data.r rVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(9924872);
        if ((((c0814p.f(rVar) ? 4 : 2) | i | (c0814p.h(function1) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            float f = androidx.compose.material3.W4.a;
            com.quizlet.data.repository.achievements.h hVarA = androidx.compose.material3.W4.a(androidx.compose.material3.D.i(c0814p), c0814p, 14);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jG = ((com.quizlet.themes.b) c0814p.j(b)).b.g();
            c0814p.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p).g, new C0416v0(C0380d.e(c0814p).k, AbstractC0382e.g));
            c0814p.p(false);
            AbstractC0725t3.a(androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "SignupScreen"), androidx.compose.runtime.internal.e.e(-2105138748, new com.quizlet.login.login.ui.g(function1, hVarA, 3), c0814p), null, null, null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(-715226087, new com.quizlet.assembly.compose.input.h(rVar, function1, hVarA, 22), c0814p), c0814p, 805306422, 188);
            c0814p = c0814p;
            if (rVar.a) {
                AbstractC3249r5.a(null, ((com.quizlet.themes.b) c0814p.j(b)).b.g(), c0814p, 0, 1);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(rVar, function1, i, 19);
        }
    }

    public static final void d(Function0 navigateBack, Function0 navigateToHome, Function0 navigateToUpsell, Function1 navigateToWebPage, Function0 navigateToEmailConfirmation, Function0 navigateToMagicLinkConfirmation, Function1 navigateToPromptParentEmail, Function1 navigateToMultipleAccountsFound, com.quizlet.login.signup.viewmodel.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        boolean z;
        int i2;
        com.quizlet.login.signup.viewmodel.a aVar2;
        com.quizlet.login.signup.viewmodel.a aVar3;
        com.quizlet.login.signup.viewmodel.a aVar4;
        Intrinsics.checkNotNullParameter(navigateBack, "navigateBack");
        Intrinsics.checkNotNullParameter(navigateToHome, "navigateToHome");
        Intrinsics.checkNotNullParameter(navigateToUpsell, "navigateToUpsell");
        Intrinsics.checkNotNullParameter(navigateToWebPage, "navigateToWebPage");
        Intrinsics.checkNotNullParameter(navigateToEmailConfirmation, "navigateToEmailConfirmation");
        Intrinsics.checkNotNullParameter(navigateToMagicLinkConfirmation, "navigateToMagicLinkConfirmation");
        Intrinsics.checkNotNullParameter(navigateToPromptParentEmail, "navigateToPromptParentEmail");
        Intrinsics.checkNotNullParameter(navigateToMultipleAccountsFound, "navigateToMultipleAccountsFound");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1491038170);
        int i3 = i | (c0814p.h(navigateBack) ? 4 : 2) | (c0814p.h(navigateToHome) ? 32 : 16) | (c0814p.h(navigateToUpsell) ? 256 : 128) | (c0814p.h(navigateToWebPage) ? 2048 : 1024) | (c0814p.h(navigateToEmailConfirmation) ? 16384 : 8192) | (c0814p.h(navigateToMagicLinkConfirmation) ? 131072 : 65536) | (c0814p.h(navigateToPromptParentEmail) ? 1048576 : 524288) | (c0814p.h(navigateToMultipleAccountsFound) ? 8388608 : 4194304) | 33554432;
        if ((38347923 & i3) == 38347922 && c0814p.x()) {
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
                z = false;
                Object objE = AbstractC3417z1.e(com.quizlet.login.signup.viewmodel.g.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                i2 = i3 & (-234881025);
                aVar2 = (com.quizlet.login.signup.viewmodel.a) objE;
            } else {
                c0814p.Q();
                i2 = i3 & (-234881025);
                z = false;
                aVar2 = aVar;
            }
            c0814p.q();
            com.quizlet.login.signup.viewmodel.g gVar = (com.quizlet.login.signup.viewmodel.g) aVar2;
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(gVar.g, c0814p);
            kotlinx.coroutines.flow.d0 d0Var = gVar.h;
            c0814p.X(677959967);
            boolean z2 = ((i2 & 29360128) == 8388608) | ((i2 & 7168) == 2048 ? true : z) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i2 & 896) == 256) | ((i2 & 14) == 4) | ((57344 & i2) == 16384) | ((458752 & i2) == 131072) | ((3670016 & i2) == 1048576);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z2 || objI == v) {
                com.quizlet.login.signup.ui.e eVar = new com.quizlet.login.signup.ui.e(navigateToWebPage, navigateToHome, navigateToUpsell, navigateBack, navigateToEmailConfirmation, navigateToMagicLinkConfirmation, navigateToPromptParentEmail, navigateToMultipleAccountsFound, null);
                c0814p.i0(eVar);
                objI = eVar;
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zF || objI2 == v) {
                objI2 = new com.quizlet.login.signup.ui.d(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            com.quizlet.login.signup.data.r rVar = (com.quizlet.login.signup.data.r) AbstractC4178x.k(unit, (Function2) objI2, c0814p, false, interfaceC0773a0G);
            c0814p.X(677982612);
            boolean zH = c0814p.h(aVar2);
            Object objI3 = c0814p.I();
            if (zH || objI3 == v) {
                aVar3 = aVar2;
                com.quizlet.login.common.navigation.d dVar = new com.quizlet.login.common.navigation.d(1, aVar3, com.quizlet.login.signup.viewmodel.a.class, "onEvent", "onEvent(Lcom/quizlet/login/signup/data/SignUpEvent;)V", 0, 13);
                c0814p.i0(dVar);
                objI3 = dVar;
            } else {
                aVar3 = aVar2;
            }
            c0814p.p(false);
            c(rVar, (Function1) ((kotlin.reflect.f) objI3), c0814p, 0);
            aVar4 = aVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.settings.ui.a(navigateBack, navigateToHome, navigateToUpsell, navigateToWebPage, navigateToEmailConfirmation, navigateToMagicLinkConfirmation, navigateToPromptParentEmail, navigateToMultipleAccountsFound, aVar4, i);
        }
    }

    public static final void e(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function1 function1, boolean z) {
        androidx.compose.ui.graphics.painter.b bVarP;
        long jA;
        long jA2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(891739748);
        int i2 = i | (c0814p.g(z) ? 4 : 2) | (c0814p.h(function1) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m.g.s();
            C0392j c0392jG = AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.h);
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(c0392jG, androidx.compose.ui.b.j, c0814p, 0);
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
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            androidx.compose.foundation.layout.I0 i0 = androidx.compose.foundation.layout.I0.a;
            String strD = AbstractC3106b5.d(c0814p, R.string.signup_student_label);
            c0814p.X(1509061734);
            androidx.compose.ui.graphics.painter.b bVarP2 = null;
            if (z) {
                ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
                bVarP = com.quizlet.ui.resources.icons.d.p(c0814p);
            } else {
                bVarP = null;
            }
            c0814p.p(false);
            if (z) {
                c0814p.X(-463607770);
                jA = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).t;
                c0814p.p(false);
            } else {
                c0814p.X(-463516196);
                jA = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).A();
                c0814p.p(false);
            }
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarA = i0.a(androidx.compose.foundation.layout.K0.c(nVar, 1.0f), 1.0f, true);
            c0814p.X(1509071324);
            int i4 = i2 & ContentType.LONG_FORM_ON_DEMAND;
            boolean z2 = i4 == 32;
            Object objI = c0814p.I();
            boolean z3 = z2;
            androidx.compose.runtime.V v = C0804k.a;
            if (z3 || objI == v) {
                objI = new com.quizlet.login.intro.ui.k(12, function1);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            Y4.a(strD, qVarA, (Function0) objI, false, false, null, null, jA, 0L, null, null, bVarP, false, c0814p, 0, 0, 6008);
            String strD2 = AbstractC3106b5.d(c0814p, R.string.signup_teacher_label);
            c0814p.X(1509079303);
            if (!z) {
                ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
                bVarP2 = com.quizlet.ui.resources.icons.d.p(c0814p);
            }
            androidx.compose.ui.graphics.painter.b bVar = bVarP2;
            c0814p.p(false);
            if (z) {
                c0814p.X(-462969604);
                jA2 = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).A();
                c0814p.p(false);
            } else {
                c0814p.X(-463061178);
                jA2 = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).t;
                c0814p.p(false);
            }
            long j = jA2;
            androidx.compose.ui.q qVarA2 = i0.a(androidx.compose.foundation.layout.K0.c(nVar, 1.0f), 1.0f, true);
            c0814p.X(1509088957);
            boolean z4 = i4 == 32;
            Object objI2 = c0814p.I();
            if (z4 || objI2 == v) {
                objI2 = new com.quizlet.login.intro.ui.k(13, function1);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            Y4.a(strD2, qVarA2, (Function0) objI2, false, false, null, null, j, 0L, null, null, bVar, false, c0814p, 0, 0, 6008);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.c(z, function1, qVar, i);
        }
    }

    public static androidx.constraintlayout.motion.widget.n f(JSONObject jSONObject, int i) {
        int i2;
        androidx.constraintlayout.motion.widget.n nVar = new androidx.constraintlayout.motion.widget.n();
        try {
            if (jSONObject.has(OTUXParamsKeys.OT_UX_BORDER_RADIUS)) {
                nVar.i = jSONObject.getString(OTUXParamsKeys.OT_UX_BORDER_RADIUS);
            }
            if (jSONObject.has("text")) {
                nVar.j = jSONObject.getString("text");
            }
            if (jSONObject.has("show")) {
                nVar.k = jSONObject.getString("show");
            }
            if (jSONObject.has("position")) {
                nVar.c = jSONObject.getInt("position");
            }
            if (jSONObject.has("positionBeforePurpose")) {
                nVar.c = jSONObject.getInt("positionBeforePurpose");
            }
            if (jSONObject.has("positionAfterPurpose") && (i2 = jSONObject.getInt("positionAfterPurpose")) != 0) {
                nVar.c = i2 + 10;
            }
            String strOptString = jSONObject.optString("color");
            String strOptString2 = jSONObject.optString("colorDark");
            String str = "";
            if (i != 11) {
                if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                    strOptString = "";
                }
                strOptString2 = strOptString;
            } else if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString2)) {
                strOptString2 = "";
            }
            nVar.e = strOptString2;
            String strOptString3 = jSONObject.optString(OTUXParamsKeys.OT_UX_TEXT_COLOR);
            String strOptString4 = jSONObject.optString("textColorDark");
            if (i == 11) {
                if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString4)) {
                    str = strOptString4;
                }
            } else if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString3)) {
                str = strOptString3;
            }
            nVar.f = str;
            nVar.d = h(jSONObject);
            return nVar;
        } catch (JSONException e) {
            com.google.android.gms.measurement.internal.Z.p("Error in parsing button property :", e, "OneTrust", 6);
            return nVar;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x0069  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static androidx.navigation.internal.m g(org.json.JSONObject r3, int r4, boolean r5, android.content.Context r6) throws org.json.JSONException {
        /*
            androidx.navigation.internal.m r0 = new androidx.navigation.internal.m
            r0.<init>()
            java.lang.String r1 = "text"
            boolean r2 = r3.has(r1)
            if (r2 == 0) goto L1c
            if (r5 == 0) goto L1c
            java.lang.String r5 = r3.getString(r1)
            if (r6 != 0) goto L16
            goto L1a
        L16:
            java.lang.String r5 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3673m4.b(r6, r5)
        L1a:
            r0.g = r5
        L1c:
            java.lang.String r5 = "textAlign"
            boolean r6 = r3.has(r5)
            if (r6 == 0) goto L2e
            java.lang.String r5 = r3.getString(r5)
            java.lang.String r5 = assistantMode.utils.studiableMetadata.b.n(r5)
            r0.f = r5
        L2e:
            java.lang.String r5 = "show"
            boolean r6 = r3.has(r5)
            if (r6 == 0) goto L4a
            java.lang.String r5 = r3.getString(r5)
            r0.e = r5
            java.lang.String r6 = "true"
            boolean r5 = r5.equalsIgnoreCase(r6)
            if (r5 == 0) goto L46
            r5 = 0
            goto L48
        L46:
            r5 = 8
        L48:
            r0.c = r5
        L4a:
            java.lang.String r5 = "textColor"
            java.lang.String r5 = r3.optString(r5)
            java.lang.String r6 = "textColorDark"
            java.lang.String r6 = r3.optString(r6)
            r1 = 11
            if (r4 != r1) goto L63
            boolean r4 = com.onetrust.otpublishers.headless.Internal.a.j(r6)
            if (r4 == 0) goto L61
            goto L69
        L61:
            r5 = r6
            goto L6b
        L63:
            boolean r4 = com.onetrust.otpublishers.headless.Internal.a.j(r5)
            if (r4 == 0) goto L6b
        L69:
            java.lang.String r5 = ""
        L6b:
            r0.b = r5
            com.google.android.gms.cloudmessaging.k r3 = h(r3)
            r0.d = r3
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3625g4.g(org.json.JSONObject, int, boolean, android.content.Context):androidx.navigation.internal.m");
    }

    public static com.google.android.gms.cloudmessaging.k h(JSONObject jSONObject) {
        com.google.android.gms.cloudmessaging.k kVar = new com.google.android.gms.cloudmessaging.k(9);
        if (jSONObject.has(OTUXParamsKeys.OT_UX_FONT_SIZE)) {
            kVar.d = jSONObject.getString(OTUXParamsKeys.OT_UX_FONT_SIZE);
        }
        return kVar;
    }
}
