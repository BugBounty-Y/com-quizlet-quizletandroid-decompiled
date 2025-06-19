package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.SharedPreferences;
import android.os.Bundle;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReason;
import com.onetrust.otpublishers.headless.UI.fragment.C4063g;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.g0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3621g0 {
    /* JADX WARN: Removed duplicated region for block: B:53:0x0150  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0154  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x016f  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x01d1  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x01d4  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x020d  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x0229  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x022b  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x0239  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x0273  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x027a  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x0295  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0298  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x02a6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(com.quizlet.login.resetpassword.data.g r34, androidx.compose.ui.q r35, androidx.compose.foundation.layout.z0 r36, kotlin.jvm.functions.Function1 r37, androidx.compose.runtime.InterfaceC0806l r38, int r39) {
        /*
            Method dump skipped, instructions count: 737
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3621g0.a(com.quizlet.login.resetpassword.data.g, androidx.compose.ui.q, androidx.compose.foundation.layout.z0, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int):void");
    }

    public static final void b(String str, Function1 function1, Function1 function12, androidx.compose.ui.q qVar, String str2, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(2031265545);
        int i2 = i | (c0814p2.f(str) ? 4 : 2) | (c0814p2.h(function1) ? 32 : 16) | (c0814p2.h(function12) ? 256 : 128) | (c0814p2.f(qVar) ? 2048 : 1024) | (c0814p2.f(str2) ? 16384 : 8192);
        if ((i2 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.X(-1307946681);
            Object objI = c0814p2.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = new androidx.compose.ui.focus.p();
                c0814p2.i0(objI);
            }
            androidx.compose.ui.focus.p pVar = (androidx.compose.ui.focus.p) objI;
            c0814p2.p(false);
            String strD = AbstractC3106b5.d(c0814p2, R.string.reset_password_email_input_label);
            com.quizlet.themes.m.g.u();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            c0814p2.X(-1307940924);
            int i3 = i2 & 14;
            boolean z = ((i2 & 896) == 256) | (i3 == 4);
            Object objI2 = c0814p2.I();
            if (z || objI2 == v) {
                objI2 = new com.quizlet.features.infra.folder.tag.composable.h(2, str, function12);
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            AbstractC3745v5.a(str, qVarY, function1, strD, null, 0, 0, null, pVar, 7, 6, (Function0) objI2, str2, false, false, null, 0, null, DefinitionKt.NO_Float_VALUE, null, null, null, c0814p2, 805306368 | i3 | ((i2 << 3) & 896), ((i2 >> 3) & 7168) | 54, 0, 8372720);
            c0814p = c0814p2;
            Unit unit = Unit.a;
            c0814p.X(-1307929897);
            Object objI3 = c0814p.I();
            if (objI3 == v) {
                objI3 = new com.quizlet.login.resetpassword.ui.b(pVar, null);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI3);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(str, function1, function12, qVar, str2, i);
        }
    }

    public static final void c(Function0 onNavigateBack, Function1 onNavigateToEmailSent, com.quizlet.login.resetpassword.viewmodel.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.login.resetpassword.viewmodel.a aVar2;
        com.quizlet.login.resetpassword.viewmodel.a aVar3;
        Intrinsics.checkNotNullParameter(onNavigateBack, "onNavigateBack");
        Intrinsics.checkNotNullParameter(onNavigateToEmailSent, "onNavigateToEmailSent");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-73870188);
        int i3 = i | (c0814p.h(onNavigateBack) ? 4 : 2) | (c0814p.h(onNavigateToEmailSent) ? 32 : 16) | 128;
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            aVar3 = aVar;
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
                Object objE = AbstractC3417z1.e(com.quizlet.login.resetpassword.viewmodel.c.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                i2 = i3 & (-897);
                aVar2 = (com.quizlet.login.resetpassword.viewmodel.a) objE;
            } else {
                c0814p.Q();
                i2 = i3 & (-897);
                aVar2 = aVar;
            }
            c0814p.q();
            androidx.compose.ui.platform.Q0 q0 = (androidx.compose.ui.platform.Q0) c0814p.j(AbstractC0955m0.n);
            com.quizlet.login.resetpassword.viewmodel.c cVar = (com.quizlet.login.resetpassword.viewmodel.c) aVar2;
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(cVar.c, c0814p);
            kotlinx.coroutines.flow.d0 d0Var = cVar.d;
            c0814p.X(1874579307);
            boolean zF = c0814p.f(q0) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i2 & 14) == 4);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (zF || objI == v) {
                objI = new com.quizlet.login.resetpassword.ui.e(q0, onNavigateToEmailSent, onNavigateBack, null);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF2 = c0814p.f(b) | c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zF2 || objI2 == v) {
                objI2 = new com.quizlet.login.resetpassword.ui.d(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            com.quizlet.login.resetpassword.data.g gVar = (com.quizlet.login.resetpassword.data.g) AbstractC4178x.k(unit, (Function2) objI2, c0814p, false, interfaceC0773a0G);
            c0814p.X(1874589676);
            boolean zH = c0814p.h(aVar2);
            Object objI3 = c0814p.I();
            if (zH || objI3 == v) {
                com.quizlet.login.common.navigation.d dVar = new com.quizlet.login.common.navigation.d(1, aVar2, com.quizlet.login.resetpassword.viewmodel.a.class, "onEvent", "onEvent(Lcom/quizlet/login/resetpassword/data/ResetPasswordEvent;)V", 0, 12);
                c0814p.i0(dVar);
                objI3 = dVar;
            }
            c0814p.p(false);
            d(gVar, (Function1) ((kotlin.reflect.f) objI3), c0814p, 0);
            aVar3 = aVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(onNavigateBack, onNavigateToEmailSent, aVar3, i, 25);
        }
    }

    public static final void d(com.quizlet.login.resetpassword.data.g gVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        int i2 = 18;
        int i3 = 2;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(796828134);
        if ((((c0814p2.f(gVar) ? 4 : 2) | i | (c0814p2.h(function1) ? 32 : 16)) & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            float f = androidx.compose.material3.W4.a;
            com.quizlet.data.repository.achievements.h hVarA = androidx.compose.material3.W4.a(androidx.compose.material3.D.i(c0814p2), c0814p2, 14);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "reset_password_screen");
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0725t3.a(qVarG, androidx.compose.runtime.internal.e.e(-1999438166, new com.quizlet.login.login.ui.g(function1, hVarA, i3), c0814p2), null, null, null, 0, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g(), 0L, c0374a, androidx.compose.runtime.internal.e.e(-925707403, new com.quizlet.assembly.compose.input.h(hVarA, gVar, function1, 21), c0814p2), c0814p, 805306422, 188);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(gVar, function1, i, i2);
        }
    }

    public static void e(androidx.fragment.app.I i, com.onetrust.otpublishers.headless.Internal.Event.a eventListenerSetter, OTConfiguration oTConfiguration, OTUIDisplayReason oTUIDisplayReason, OTPublishersHeadlessSDK otPublishersHeadlessSDK) {
        boolean z;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z2;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar2;
        if (com.onetrust.otpublishers.headless.Internal.a.g(i, OTFragmentTags.OT_BANNER_FRAGMENT_TAG)) {
            return;
        }
        SharedPreferences sharedPreferences = i.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (new com.onetrust.otpublishers.headless.Internal.profile.c(i).t()) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(i, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            z = false;
            fVar = null;
        }
        StringBuilder sb = new StringBuilder("ui type ");
        sb.append((z ? fVar : sharedPreferences).getInt("OT_UI_MODE_TYPE", 102));
        OTLogger.c("OneTrust", 4, sb.toString());
        if (z) {
            sharedPreferences = fVar;
        }
        if (sharedPreferences.getInt("OT_UI_MODE_TYPE", 102) == 101) {
            com.onetrust.otpublishers.headless.UI.TVUI.fragments.g gVar = new com.onetrust.otpublishers.headless.UI.TVUI.fragments.g();
            Bundle bundle = new Bundle();
            bundle.putString(OTFragmentTags.FRAGMENT_TAG, OTFragmentTags.OT_TV_MAIN_FRAGMENT_TAG);
            gVar.setArguments(bundle);
            gVar.v = eventListenerSetter;
            gVar.w = 0;
            gVar.A = oTConfiguration;
            com.google.mlkit.common.internal.model.a.l(gVar, i, OTFragmentTags.OT_TV_MAIN_FRAGMENT_TAG);
        } else {
            C4063g.A.getClass();
            Intrinsics.checkNotNullParameter(OTFragmentTags.OT_BANNER_FRAGMENT_TAG, "fragmentTag");
            Intrinsics.checkNotNullParameter(eventListenerSetter, "eventListenerSetter");
            Bundle bundleA = AbstractC3206m6.a(new Pair(OTFragmentTags.FRAGMENT_TAG, OTFragmentTags.OT_BANNER_FRAGMENT_TAG));
            C4063g c4063g = new C4063g();
            c4063g.setArguments(bundleA);
            c4063g.t = eventListenerSetter;
            c4063g.u = oTConfiguration;
            if (oTConfiguration != null && oTConfiguration.issSncOTUIWithBYOUIMethodsEnabled()) {
                Intrinsics.checkNotNullParameter(otPublishersHeadlessSDK, "otPublishersHeadlessSDK");
                c4063g.q = otPublishersHeadlessSDK;
            }
            com.google.mlkit.common.internal.model.a.l(c4063g, i, OTFragmentTags.OT_BANNER_FRAGMENT_TAG);
        }
        OTLogger.c("OneTrust", 4, "Showing Banner");
        OTLogger.c("OneTrust", 4, oTUIDisplayReason.logReason());
        androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(1, 4);
        mVar.f = oTUIDisplayReason;
        if (eventListenerSetter != null) {
            eventListenerSetter.a(mVar);
        } else {
            OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
        }
        SharedPreferences sharedPreferences2 = i.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (com.google.android.gms.measurement.internal.Z.r(Boolean.FALSE, i.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER"), 0), "OT_ENABLE_MULTI_PROFILE")) {
            fVar2 = new com.onetrust.otpublishers.headless.Internal.Preferences.f(i, sharedPreferences2, sharedPreferences2.getString("OT_ACTIVE_PROFILE_ID", ""));
            z2 = true;
        } else {
            z2 = false;
            fVar2 = null;
        }
        if (z2) {
            sharedPreferences2 = fVar2;
        }
        if (sharedPreferences2.getInt("OneTrustBannerShownToUser", -1) < 1) {
            com.onetrust.otpublishers.headless.Internal.a.b(i, 1);
        }
    }
}
