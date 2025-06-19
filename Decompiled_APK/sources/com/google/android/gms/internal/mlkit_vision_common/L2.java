package com.google.android.gms.internal.mlkit_vision_common;

import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.foundation.layout.C0416v0;
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
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.AdvertisementType;
import com.comscore.streaming.ContentType;
import com.facebook.AccessToken;
import com.facebook.FacebookException;
import com.facebook.GraphRequest$ParcelableResourceWithMimeType;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3137f0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3307y6;
import com.google.android.gms.internal.mlkit_vision_barcode.Q5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.File;
import java.util.Set;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class L2 {
    public static final void a(Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1965489267);
        int i2 = (c0814p.h(function0) ? 4 : 2) | i | (c0814p.h(function02) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
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
            d((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND, c0814p, null, function0);
            c(function02, c0814p, (i2 >> 3) & 14);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.upload.composables.common.d(function0, function02, i, 1);
        }
    }

    public static final void b(androidx.compose.foundation.layout.z0 z0Var, com.quizlet.features.settings.data.states.y yVar, androidx.compose.runtime.internal.j jVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.foundation.layout.z0 z0Var2;
        int i2;
        boolean z = true;
        int i3 = 4;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1493331720);
        if ((i & 6) == 0) {
            z0Var2 = z0Var;
            i2 = (c0814p.f(z0Var2) ? 4 : 2) | i;
        } else {
            z0Var2 = z0Var;
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p.f(yVar) : c0814p.h(yVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(jVar) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            androidx.compose.ui.q qVarT = AbstractC0382e.t(androidx.compose.ui.n.b, Q5.a(z0Var2));
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(AbstractC0382e.w(qVarT, f, DefinitionKt.NO_Float_VALUE, 2).g(androidx.compose.foundation.layout.K0.c), "settingsColumn");
            mVar.s();
            mVar.s();
            androidx.compose.foundation.layout.A0 a0E = AbstractC0382e.e(DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, z0Var2.a() + f, 5);
            C0380d c0380d = AbstractC0398m.a;
            mVar.p();
            C0392j c0392jG = AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.j);
            c0814p.X(416238650);
            boolean z2 = (((i2 & ContentType.LONG_FORM_ON_DEMAND) ^ 48) > 32 && c0814p.h(yVar)) || (i2 & 48) == 32;
            if ((((i2 & 896) ^ 384) <= 256 || !c0814p.f(jVar)) && (i2 & 384) != 256) {
                z = false;
            }
            boolean z3 = z | z2;
            Object objI = c0814p.I();
            if (z3 || objI == C0804k.a) {
                objI = new com.quizlet.features.setpage.header.ui.g(i3, yVar, jVar);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3137f0.a(qVarG, null, a0E, c0392jG, null, null, false, (Function1) objI, c0814p, 0, AdvertisementType.BRANDED_AS_CONTENT);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 7, z0Var2, yVar, jVar);
        }
    }

    public static final void c(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1716871464);
        if ((i & 6) == 0) {
            i2 = i | (c0814p.h(function0) ? 4 : 2);
        } else {
            i2 = i;
        }
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(androidx.compose.ui.n.b, 1.0f);
            com.quizlet.themes.m.g.s();
            Y4.b(AbstractC3106b5.d(c0814p, R.string.delete_account), AbstractC0382e.y(qVarC, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), function0, false, null, null, 0L, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.a(), null, null, null, c0814p, (i2 << 6) & 896, 0, 3832);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.screens.b(i, 2, function0);
        }
    }

    public static final void d(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.n nVar, Function0 onLogOutClick) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(onLogOutClick, "onLogOutClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1575413267);
        int i2 = i | 6;
        if ((i & 48) == 0) {
            i2 |= c0814p.h(onLogOutClick) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            Y4.b(AbstractC3106b5.d(c0814p, R.string.logout), androidx.compose.foundation.layout.K0.c(nVar3, 1.0f), onLogOutClick, false, null, null, 0L, 0L, null, null, null, c0814p, (i2 << 3) & 896, 0, 4088);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.buttons.e0(nVar2, onLogOutClick, i);
        }
    }

    public static final void e(com.quizlet.features.settings.data.states.y yVar, androidx.compose.runtime.internal.j jVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1702926848);
        if ((((c0814p.f(yVar) ? 4 : 2) | i | (c0814p.f(jVar) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            long jG = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g();
            c0814p.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p).g, new C0416v0(C0380d.e(c0814p).k, AbstractC0382e.g));
            c0814p.p(false);
            AbstractC0725t3.a(null, androidx.compose.runtime.internal.e.e(-1215407684, new com.quizlet.features.practicetest.results.i(12, yVar, jVar), c0814p), null, null, null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(-1906722479, new com.quizlet.features.settings.composables.s(yVar, jVar, 6), c0814p), c0814p, 805306416, 189);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(yVar, jVar, i, 7);
        }
    }

    public static final void f(androidx.navigation.H h, final com.quizlet.features.settings.viewmodels.p pVar, com.quizlet.features.settings.viewmodels.o oVar, int i, InterfaceC0806l interfaceC0806l, int i2) {
        C0814p c0814p;
        com.quizlet.features.settings.viewmodels.o oVar2;
        int i3;
        int i4;
        androidx.compose.runtime.V v;
        com.quizlet.features.settings.viewmodels.o oVar3;
        com.quizlet.features.infra.logout.composables.a aVar;
        C0814p c0814p2;
        com.quizlet.features.settings.viewmodels.o oVar4;
        int i5;
        final int i6 = 0;
        C0814p c0814p3 = (C0814p) interfaceC0806l;
        c0814p3.Z(-1955132524);
        int i7 = i2 | (c0814p3.h(h) ? 4 : 2) | (c0814p3.f(pVar) ? 32 : 16) | 1152;
        if ((i7 & 1171) == 1170 && c0814p3.x()) {
            c0814p3.Q();
            oVar4 = oVar;
            i5 = i;
            c0814p2 = c0814p3;
        } else {
            c0814p3.S();
            if ((i2 & 1) == 0 || c0814p3.w()) {
                c0814p3.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p3);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p3);
                c0814p3.Y(1729797275);
                Object objE = AbstractC3417z1.e(com.quizlet.features.settings.viewmodels.u.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p3);
                c0814p = c0814p3;
                c0814p.p(false);
                c0814p.p(false);
                oVar2 = (com.quizlet.features.settings.viewmodels.o) objE;
                i3 = i7 & (-8065);
                i4 = AbstractC3205m5.g(c0814p).a;
            } else {
                c0814p3.Q();
                i3 = i7 & (-8065);
                i4 = i;
                c0814p = c0814p3;
                oVar2 = oVar;
            }
            int i8 = i3;
            c0814p.q();
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(((com.quizlet.features.settings.viewmodels.I) pVar).n, c0814p);
            com.quizlet.features.settings.data.models.f reAuthType = ((com.quizlet.features.settings.data.states.y) interfaceC0773a0M.getValue()).e;
            Intrinsics.checkNotNullParameter(reAuthType, "reAuthType");
            c0814p.X(1222350008);
            com.quizlet.assembly.compose.modals.x cantChangeUsernameModalState = Y5.h(false, false, c0814p, 48, 5);
            com.quizlet.assembly.compose.modals.x passwordReAuthenticationModalState = Y5.h(false, false, c0814p, 48, 5);
            com.quizlet.assembly.compose.modals.x googleReAuthenticationModalState = Y5.h(false, false, c0814p, 48, 5);
            com.quizlet.assembly.compose.modals.x facebookReAuthenticationModalState = Y5.h(false, false, c0814p, 48, 5);
            Intrinsics.checkNotNullParameter(reAuthType, "reAuthType");
            Intrinsics.checkNotNullParameter(cantChangeUsernameModalState, "cantChangeUsernameModalState");
            Intrinsics.checkNotNullParameter(passwordReAuthenticationModalState, "passwordReAuthenticationModalState");
            Intrinsics.checkNotNullParameter(googleReAuthenticationModalState, "googleReAuthenticationModalState");
            Intrinsics.checkNotNullParameter(facebookReAuthenticationModalState, "facebookReAuthenticationModalState");
            final com.quizlet.data.interactor.folderwithcreator.m mVar = new com.quizlet.data.interactor.folderwithcreator.m();
            mVar.a = reAuthType;
            mVar.b = cantChangeUsernameModalState;
            mVar.c = passwordReAuthenticationModalState;
            mVar.d = googleReAuthenticationModalState;
            mVar.e = facebookReAuthenticationModalState;
            c0814p.p(false);
            com.quizlet.features.infra.logout.composables.a aVarA = AbstractC3307y6.a(c0814p);
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            boolean z = i4 == 0;
            c0814p.X(-2039453749);
            boolean zH = c0814p.h(oVar2);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v2 = C0804k.a;
            if (zH || objI == v2) {
                v = v2;
                oVar3 = oVar2;
                com.quizlet.features.notes.detail.composables.magicnotesdetail.G g = new com.quizlet.features.notes.detail.composables.magicnotesdetail.G(1, oVar3, com.quizlet.features.settings.viewmodels.o.class, "onChangeRequest", "onChangeRequest(Lcom/quizlet/features/settings/data/models/ChangeSettingsRequestType;)V", 0, 29);
                c0814p.i0(g);
                objI = g;
            } else {
                oVar3 = oVar2;
                v = v2;
            }
            c0814p.p(false);
            final Function1 function1 = (Function1) ((kotlin.reflect.f) objI);
            com.quizlet.features.settings.data.models.f fVar = ((com.quizlet.features.settings.data.states.y) interfaceC0773a0M.getValue()).e;
            androidx.compose.runtime.V v3 = v;
            boolean z2 = z;
            com.quizlet.features.setpage.header.ui.a onBackClick = new com.quizlet.features.setpage.header.ui.a(0, pVar, com.quizlet.features.settings.viewmodels.p.class, "onBackClick", "onBackClick()V", 0, 17);
            com.quizlet.data.repository.explanations.myexplanations.a subscriptionActions = new com.quizlet.data.repository.explanations.myexplanations.a(new com.quizlet.features.setpage.header.ui.a(0, pVar, com.quizlet.features.settings.viewmodels.p.class, "onManageSubscriptionClick", "onManageSubscriptionClick()V", 0, 20), new com.quizlet.features.setpage.header.ui.a(0, pVar, com.quizlet.features.settings.viewmodels.p.class, "onUpgradeClick", "onUpgradeClick()V", 0, 19));
            Function0 onChangeUsernameClick = new Function0() { // from class: com.quizlet.features.settings.composables.q
                @Override // kotlin.jvm.functions.Function0
                public final Object invoke() {
                    switch (i6) {
                        case 0:
                            function1.invoke(com.quizlet.features.settings.data.models.b.a);
                            mVar.m();
                            pVar.getClass();
                            break;
                        case 1:
                            function1.invoke(com.quizlet.features.settings.data.models.b.b);
                            mVar.m();
                            pVar.getClass();
                            break;
                        default:
                            function1.invoke(com.quizlet.features.settings.data.models.b.c);
                            mVar.m();
                            pVar.getClass();
                            break;
                    }
                    return Unit.a;
                }
            };
            com.quizlet.featuregate.growthbook.a onCantChangeUsernameClick = new com.quizlet.featuregate.growthbook.a(mVar, pVar);
            final int i9 = 1;
            Function0 onEmailSectionClick = new Function0() { // from class: com.quizlet.features.settings.composables.q
                @Override // kotlin.jvm.functions.Function0
                public final Object invoke() {
                    switch (i9) {
                        case 0:
                            function1.invoke(com.quizlet.features.settings.data.models.b.a);
                            mVar.m();
                            pVar.getClass();
                            break;
                        case 1:
                            function1.invoke(com.quizlet.features.settings.data.models.b.b);
                            mVar.m();
                            pVar.getClass();
                            break;
                        default:
                            function1.invoke(com.quizlet.features.settings.data.models.b.c);
                            mVar.m();
                            pVar.getClass();
                            break;
                    }
                    return Unit.a;
                }
            };
            com.quizlet.features.settings.composables.r onChangePasswordClick = new com.quizlet.features.settings.composables.r(h, z2, pVar);
            final int i10 = 2;
            Function0 onCreatePasswordClick = new Function0() { // from class: com.quizlet.features.settings.composables.q
                @Override // kotlin.jvm.functions.Function0
                public final Object invoke() {
                    switch (i10) {
                        case 0:
                            function1.invoke(com.quizlet.features.settings.data.models.b.a);
                            mVar.m();
                            pVar.getClass();
                            break;
                        case 1:
                            function1.invoke(com.quizlet.features.settings.data.models.b.b);
                            mVar.m();
                            pVar.getClass();
                            break;
                        default:
                            function1.invoke(com.quizlet.features.settings.data.models.b.c);
                            mVar.m();
                            pVar.getClass();
                            break;
                    }
                    return Unit.a;
                }
            };
            Intrinsics.checkNotNullParameter(onChangeUsernameClick, "onChangeUsernameClick");
            Intrinsics.checkNotNullParameter(onCantChangeUsernameClick, "onCantChangeUsernameClick");
            Intrinsics.checkNotNullParameter(onEmailSectionClick, "onEmailSectionClick");
            Intrinsics.checkNotNullParameter(onChangePasswordClick, "onChangePasswordClick");
            Intrinsics.checkNotNullParameter(onCreatePasswordClick, "onCreatePasswordClick");
            C1608n personalInfoActions = new C1608n();
            personalInfoActions.a = onChangeUsernameClick;
            personalInfoActions.b = onCantChangeUsernameClick;
            personalInfoActions.c = onEmailSectionClick;
            personalInfoActions.d = onChangePasswordClick;
            personalInfoActions.e = onCreatePasswordClick;
            com.quizlet.features.settings.composables.j offlineStudyingActions = new com.quizlet.features.settings.composables.j(new com.quizlet.features.setpage.header.ui.a(0, pVar, com.quizlet.features.settings.viewmodels.p.class, "onOfflineUnavailableClick", "onOfflineUnavailableClick()V", 0, 21), new com.quizlet.features.settings.composables.x(1, pVar, com.quizlet.features.settings.viewmodels.p.class, "onOfflineStudyingToggled", "onOfflineStudyingToggled(Z)V", 0, 0));
            C0814p c0814p4 = c0814p;
            com.quizlet.features.settings.composables.n preferencesActions = new com.quizlet.features.settings.composables.n(new com.quizlet.features.settings.composables.x(1, pVar, com.quizlet.features.settings.viewmodels.p.class, "onPushNotificationsToggled", "onPushNotificationsToggled(Z)V", 0, 1), new com.quizlet.features.settings.composables.x(1, pVar, com.quizlet.features.settings.viewmodels.p.class, "onSoundEffectsToggled", "onSoundEffectsToggled(Z)V", 0, 2), new com.quizlet.features.setpage.header.ui.a(0, pVar, com.quizlet.features.settings.viewmodels.p.class, "onAdsAndCookiesPreferencesClick", "onAdsAndCookiesPreferencesClick()V", 0, 11));
            com.google.mlkit.vision.documentscanner.internal.c appearanceActions = new com.google.mlkit.vision.documentscanner.internal.c(new com.quizlet.features.settings.composables.r(z2, h, pVar));
            com.quizlet.features.settings.composables.a aboutActions = new com.quizlet.features.settings.composables.a(new com.quizlet.features.setpage.header.ui.a(0, pVar, com.quizlet.features.settings.viewmodels.p.class, "onPrivacyPolicyClick", "onPrivacyPolicyClick()V", 0, 12), new com.quizlet.features.setpage.header.ui.a(0, pVar, com.quizlet.features.settings.viewmodels.p.class, "onTermsOfServiceClick", "onTermsOfServiceClick()V", 0, 13), new com.quizlet.features.setpage.header.ui.a(0, pVar, com.quizlet.features.settings.viewmodels.p.class, "onOpenSourceLicensesClick", "onOpenSourceLicensesClick()V", 0, 14), new com.quizlet.features.setpage.header.ui.a(0, pVar, com.quizlet.features.settings.viewmodels.p.class, "onHelpCenterClick", "onHelpCenterClick()V", 0, 15));
            com.quizlet.features.setpage.header.ui.a onLogOutClick = new com.quizlet.features.setpage.header.ui.a(0, pVar, com.quizlet.features.settings.viewmodels.p.class, "onLogOutClick", "onLogOutClick()V", 0, 16);
            com.quizlet.features.setpage.header.ui.a onDevToolsClick = new com.quizlet.features.setpage.header.ui.a(0, pVar, com.quizlet.features.settings.viewmodels.p.class, "onDevToolsClick", "onDevToolsClick()V", 0, 18);
            com.quizlet.features.questionnaire.screens.c onDeleteAccountClick = new com.quizlet.features.questionnaire.screens.c(8, fVar, h);
            Intrinsics.checkNotNullParameter(onBackClick, "onBackClick");
            Intrinsics.checkNotNullParameter(subscriptionActions, "subscriptionActions");
            Intrinsics.checkNotNullParameter(personalInfoActions, "personalInfoActions");
            Intrinsics.checkNotNullParameter(offlineStudyingActions, "offlineStudyingActions");
            Intrinsics.checkNotNullParameter(preferencesActions, "preferencesActions");
            Intrinsics.checkNotNullParameter(appearanceActions, "appearanceActions");
            Intrinsics.checkNotNullParameter(aboutActions, "aboutActions");
            Intrinsics.checkNotNullParameter(onLogOutClick, "onLogOutClick");
            Intrinsics.checkNotNullParameter(onDevToolsClick, "onDevToolsClick");
            Intrinsics.checkNotNullParameter(onDeleteAccountClick, "onDeleteAccountClick");
            androidx.compose.runtime.internal.j jVar = new androidx.compose.runtime.internal.j();
            jVar.a = onBackClick;
            jVar.b = subscriptionActions;
            jVar.c = personalInfoActions;
            jVar.d = offlineStudyingActions;
            jVar.e = preferencesActions;
            jVar.f = appearanceActions;
            jVar.g = aboutActions;
            jVar.h = onLogOutClick;
            jVar.i = onDevToolsClick;
            jVar.j = onDeleteAccountClick;
            kotlinx.coroutines.flow.d0 d0Var = ((com.quizlet.features.settings.viewmodels.I) pVar).i.f;
            c0814p4.X(-2039447985);
            boolean zH2 = c0814p4.h(aVarA);
            Object objI2 = c0814p4.I();
            if (zH2 || objI2 == v3) {
                aVar = aVarA;
                objI2 = new androidx.compose.runtime.internal.c(2, aVar, com.quizlet.features.infra.logout.composables.a.class, "showLogOutWarningModal", "showLogOutWarningModal(Lcom/quizlet/data/model/LogoutWarning;)V", 4, 10);
                c0814p4.i0(objI2);
            } else {
                aVar = aVarA;
            }
            c0814p4.p(false);
            c0814p4.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p4.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI2, c0814p4);
            Unit unit = Unit.a;
            c0814p4.X(1667431386);
            boolean zF = c0814p4.f(b) | c0814p4.h(j) | c0814p4.h(d0Var) | c0814p4.f(interfaceC0773a0D);
            Object objI3 = c0814p4.I();
            if (zF || objI3 == v3) {
                objI3 = new com.quizlet.features.settings.composables.v(interfaceC0773a0D, j, null, d0Var);
                c0814p4.i0(objI3);
            }
            c0814p4.p(false);
            e((com.quizlet.features.settings.data.states.y) AbstractC4178x.k(unit, (Function2) objI3, c0814p4, false, interfaceC0773a0M), jVar, c0814p4, 0);
            com.quizlet.features.settings.data.models.f fVar2 = ((com.quizlet.features.settings.data.states.y) interfaceC0773a0M.getValue()).e;
            c0814p4.X(-2039435931);
            boolean zH3 = c0814p4.h(h) | c0814p4.g(z2);
            Object objI4 = c0814p4.I();
            if (zH3 || objI4 == v3) {
                objI4 = new androidx.navigation.compose.internal.a(h, z2);
                c0814p4.i0(objI4);
            }
            Function2 function2 = (Function2) objI4;
            c0814p4.p(false);
            c0814p4.X(-2039431006);
            boolean z3 = (((i8 & ContentType.LONG_FORM_ON_DEMAND) ^ 48) > 32 && c0814p4.h(pVar)) || (i8 & 48) == 32;
            Object objI5 = c0814p4.I();
            if (z3 || objI5 == v3) {
                objI5 = new com.quizlet.features.notes.detail.composables.magicnotesdetail.G(1, pVar, com.quizlet.features.settings.viewmodels.p.class, "onLogOutConfirmed", "onLogOutConfirmed(Lcom/quizlet/data/model/LogoutWarning;)V", 0, 28);
                c0814p4.i0(objI5);
            }
            c0814p4.p(false);
            com.quizlet.features.settings.viewmodels.o oVar5 = oVar3;
            AbstractC3465h3.b(fVar2, mVar, aVar, null, null, oVar5, function2, (Function1) ((kotlin.reflect.f) objI5), c0814p4, 576);
            c0814p2 = c0814p4;
            oVar4 = oVar5;
            i5 = i4;
        }
        C0813o0 c0813o0R = c0814p2.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(h, pVar, oVar4, i5, i2);
        }
    }

    public static final void g(com.quizlet.features.settings.data.states.y yVar, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(811658088);
        int i2 = i | (c0814p.f(yVar) ? 4 : 2) | (c0814p.h(function0) ? 32 : 16) | (c0814p.h(function02) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            N2.b(null, AbstractC3106b5.d(c0814p, R.string.settings_title), 0L, null, function0, androidx.compose.runtime.internal.e.e(-1810273720, new com.quizlet.features.questiontypes.mcq.ui.c(3, yVar, function02), c0814p), c0814p, ((i2 << 9) & 57344) | 196608, 13);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 15, yVar, function0, function02);
        }
    }

    public static final com.facebook.t h(AccessToken accessToken, Uri imageUri, com.facebook.internal.N n) {
        Intrinsics.checkNotNullParameter(imageUri, "imageUri");
        String path = imageUri.getPath();
        boolean zEqualsIgnoreCase = "file".equalsIgnoreCase(imageUri.getScheme());
        com.facebook.x xVar = com.facebook.x.b;
        if (zEqualsIgnoreCase && path != null) {
            GraphRequest$ParcelableResourceWithMimeType graphRequest$ParcelableResourceWithMimeType = new GraphRequest$ParcelableResourceWithMimeType(ParcelFileDescriptor.open(new File(path), 268435456));
            Bundle bundle = new Bundle(1);
            bundle.putParcelable("file", graphRequest$ParcelableResourceWithMimeType);
            return new com.facebook.t(accessToken, "me/staging_resources", bundle, xVar, n);
        }
        if (!"content".equalsIgnoreCase(imageUri.getScheme())) {
            throw new FacebookException("The image Uri must be either a file:// or content:// Uri");
        }
        GraphRequest$ParcelableResourceWithMimeType graphRequest$ParcelableResourceWithMimeType2 = new GraphRequest$ParcelableResourceWithMimeType(imageUri);
        Bundle bundle2 = new Bundle(1);
        bundle2.putParcelable("file", graphRequest$ParcelableResourceWithMimeType2);
        return new com.facebook.t(accessToken, "me/staging_resources", bundle2, xVar, n);
    }
}
