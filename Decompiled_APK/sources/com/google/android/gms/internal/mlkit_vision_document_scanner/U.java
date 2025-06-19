package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.SharedPreferences;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.HorizontalAlignElement;
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
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class U {
    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.n nVar, String str, Function0 function0, Function0 function02) {
        String str2;
        Function0 function03;
        Function0 function04;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-651240836);
        int i2 = (c0814p.f(str) ? 4 : 2) | i | (c0814p.h(function0) ? 32 : 16) | (c0814p.h(function02) ? 256 : 128) | 3072;
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            str2 = str;
            function03 = function0;
            function04 = function02;
        } else {
            nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            long jN = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.n();
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.f();
            float f = com.quizlet.ui.resources.designsystem.generated.f.i;
            mVar.f();
            androidx.compose.ui.q qVarF = AbstractC0460p.f(qVarC, jN, androidx.compose.foundation.shape.e.b(f, f, 12));
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarF);
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
            C0776c.E(c0814p, qVarC2, C0914j.d);
            com.google.android.gms.internal.mlkit_vision_barcode.L5.f(0, 0, c0814p, new HorizontalAlignElement(androidx.compose.ui.b.n));
            str2 = str;
            function03 = function0;
            function04 = function02;
            b(i2 & 1022, c0814p, null, str2, function03, function04);
            c0814p.p(true);
        }
        androidx.compose.ui.n nVar2 = nVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.c(str2, function03, function04, nVar2, i);
        }
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.n nVar, String str, Function0 function0, Function0 function02) {
        int i2;
        androidx.compose.ui.n nVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-325868799);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(str) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function02) ? 256 : 128;
        }
        int i3 = i2 | 3072;
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarU = AbstractC0460p.u(AbstractC0382e.u(qVarC, f), AbstractC0460p.r(c0814p), false, 14);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarU);
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
            C0776c.E(c0814p, qVarC2, C0914j.d);
            mVar.s();
            androidx.compose.ui.q qVarK = androidx.compose.foundation.layout.K0.k(AbstractC0382e.y(nVar3, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 88);
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            androidx.compose.ui.q qVarG = qVarK.g(new HorizontalAlignElement(gVar));
            com.quizlet.themes.e.a(c0814p).d.getClass();
            c0814p.X(-136170276);
            androidx.compose.ui.graphics.painter.b bVarA = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(R.drawable.ic_brand_settings, c0814p, 0);
            c0814p.p(false);
            AbstractC0460p.c(bVarA, null, qVarG, null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 48, 120);
            mVar.q();
            androidx.compose.ui.q qVarG2 = AbstractC0382e.y(nVar3, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13).g(new HorizontalAlignElement(gVar));
            String strC = AbstractC3106b5.c(R.string.magic_link_logged_in_title, new Object[]{str}, c0814p);
            androidx.compose.runtime.B b = com.quizlet.themes.w.b;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b)).e;
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            androidx.compose.material3.Q4.b(strC, qVarG2, ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65016);
            mVar.s();
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.magic_link_logged_in_message), AbstractC0382e.y(nVar3, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13).g(new HorizontalAlignElement(gVar)), ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).o, c0814p, 0, 0, 65016);
            mVar.p();
            W4.a(AbstractC3106b5.c(R.string.magic_link_logged_in_stay_logged_in_button, new Object[]{str}, c0814p), androidx.compose.foundation.layout.K0.c(AbstractC0382e.y(nVar3, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.j, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 1.0f), function0, false, null, null, null, null, null, false, c0814p, (i3 << 3) & 896, 1016);
            mVar.s();
            Y4.b(AbstractC3106b5.d(c0814p, R.string.magic_link_logged_in_switch_account_button), androidx.compose.foundation.layout.K0.c(AbstractC0382e.y(nVar3, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 1.0f), function02, false, null, null, 0L, 0L, null, null, null, c0814p, i3 & 896, 0, 4088);
            c0814p = c0814p;
            c0814p.p(true);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i((Object) str, (Object) function0, (Object) function02, (Object) nVar2, i, 28);
        }
    }

    public static final void c(com.quizlet.login.magiclink.viewmodel.g viewModel, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.login.magiclink.viewmodel.g gVar;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(239018842);
        int i2 = (c0814p2.f(viewModel) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            gVar = viewModel;
            c0814p = c0814p2;
        } else {
            String str = (String) C0776c.m(viewModel.d, c0814p2).getValue();
            c0814p2.X(302374203);
            int i3 = i2 & 14;
            boolean z = i3 == 4;
            Object objI = c0814p2.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                com.quizlet.learn.ads.g gVar2 = new com.quizlet.learn.ads.g(0, viewModel, com.quizlet.login.magiclink.viewmodel.a.class, "onStayLoggedIn", "onStayLoggedIn()V", 0, 25);
                c0814p2.i0(gVar2);
                objI = gVar2;
            }
            c0814p2.p(false);
            Function0 function0 = (Function0) ((kotlin.reflect.f) objI);
            c0814p2.X(302375933);
            boolean z2 = i3 == 4;
            Object objI2 = c0814p2.I();
            if (z2 || objI2 == v) {
                objI2 = new com.quizlet.learn.ads.g(0, viewModel, com.quizlet.login.magiclink.viewmodel.a.class, "onSwitchAccounts", "onSwitchAccounts()V", 0, 26);
                gVar = viewModel;
                c0814p2.i0(objI2);
            } else {
                gVar = viewModel;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            a(0, c0814p, null, str, function0, (Function0) ((kotlin.reflect.f) objI2));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.a(gVar, i, 6);
        }
    }

    public static int d(String str, JSONObject jSONObject) {
        if (!jSONObject.has(str)) {
            return -1;
        }
        String strOptString = jSONObject.optJSONObject(str).optString("userConsentStatus");
        return ("ACTIVE".equalsIgnoreCase(strOptString) || "OPT_IN".equalsIgnoreCase(strOptString)) ? 1 : 0;
    }

    public static void e(com.onetrust.otpublishers.headless.Internal.Preferences.d dVar, JSONObject jSONObject, JSONObject jSONObject2, JSONObject jSONObject3) {
        SharedPreferences.Editor editorEdit = dVar.b().edit();
        editorEdit.putString("OT_UC_PURPOSES_PURPOSE_SERVER_DATA", String.valueOf(jSONObject));
        editorEdit.putString("OT_UC_PURPOSES_TOPIC_SERVER_DATA", String.valueOf(jSONObject2));
        editorEdit.putString("OT_UC_PURPOSES_CUSTOM_PREF_OPTIONS_SERVER_DATA", String.valueOf(jSONObject3));
        editorEdit.apply();
    }

    public static boolean f(String str, boolean z, JSONObject jSONObject, String str2) throws JSONException {
        if (str.equalsIgnoreCase(str2)) {
            jSONObject.put("userConsentStatus", z ? "OPT_IN" : "OPT_OUT");
            return true;
        }
        OTLogger.c("UCPurposesDataHandler", 5, "Invalid ID passed to update UCP Consent values");
        return false;
    }
}
