package com.onetrust.otpublishers.headless.UI.TVUI.datautils;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.camera.camera2.internal.c0;
import androidx.constraintlayout.motion.widget.n;
import androidx.navigation.internal.m;
import com.airbnb.lottie.animation.keyframe.q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Preferences.f;
import com.quizlet.features.match.settings.MatchSettingsData;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class a {
    public static a h;
    public boolean a;
    public Object b;
    public Object e;
    public Object f;
    public Object c = "";
    public Object d = "";
    public Object g = new n();

    public static void c(n nVar, String str, String str2, String str3) {
        String str4;
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.j)) {
            nVar.j = str;
        }
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.e)) {
            nVar.e = str2;
        }
        b bVarA = b.a();
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.f)) {
            nVar.f = str3;
        }
        if (bVarA.s) {
            nVar.g = str3;
            str4 = bVarA.f;
        } else {
            str4 = "";
            nVar.g = "";
        }
        nVar.n = str4;
        nVar.b = (!AbstractC3605e0.a((String) nVar.k) || com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.j)) ? 8 : 0;
        nVar.l = bVarA.e;
        nVar.m = bVarA.f;
    }

    public void a(Context context) {
        boolean z;
        f fVar;
        try {
            JSONObject jSONObject = (JSONObject) this.b;
            if (jSONObject == null) {
                SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                if (AbstractC3605e0.a(new com.onetrust.otpublishers.headless.Internal.Preferences.d(context, "OTT_DEFAULT_USER").b().getString("OT_ENABLE_MULTI_PROFILE", Boolean.FALSE.toString()))) {
                    fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                    z = true;
                } else {
                    z = false;
                    fVar = null;
                }
                SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                if (new com.onetrust.otpublishers.headless.Internal.profile.c(context).t()) {
                    SharedPreferences sharedPreferences3 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preference.OTT_USER_" + new com.onetrust.otpublishers.headless.Internal.profile.c(context).n(sharedPreferences2.getString("OT_ACTIVE_PROFILE_ID", "")), 0);
                    sharedPreferences2.edit();
                    sharedPreferences3.edit();
                }
                SharedPreferences sharedPreferences4 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                if (new com.onetrust.otpublishers.headless.Internal.profile.c(context).t()) {
                    SharedPreferences sharedPreferences5 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preference.OTT_USER_" + new com.onetrust.otpublishers.headless.Internal.profile.c(context).n(sharedPreferences4.getString("OT_ACTIVE_PROFILE_ID", "")), 0);
                    sharedPreferences4.edit();
                    sharedPreferences5.edit();
                }
                if (z) {
                    sharedPreferences = fVar;
                }
                String string = sharedPreferences.getString("OTT_BANNER_DATA", null);
                jSONObject = !com.onetrust.otpublishers.headless.Internal.a.j(string) ? new JSONObject(string) : null;
            }
            this.b = jSONObject;
            String strOptString = jSONObject.optString("BackgroundColor");
            this.c = ((JSONObject) this.b).optString("TextColor");
            String strOptString2 = ((JSONObject) this.b).optString("BannerTitle");
            String strOptString3 = ((JSONObject) this.b).optString("AlertNoticeText");
            String strOptString4 = ((JSONObject) this.b).optString("AlertAllowCookiesText");
            String strOptString5 = ((JSONObject) this.b).optString("BannerRejectAllButtonText");
            String strOptString6 = ((JSONObject) this.b).optString("AlertMoreInfoText");
            String strOptString7 = ((JSONObject) this.b).optString("ButtonColor");
            String strOptString8 = ((JSONObject) this.b).optString("ButtonColor");
            String strOptString9 = ((JSONObject) this.b).optString("BannerMPButtonColor");
            String strOptString10 = ((JSONObject) this.b).optString("ButtonTextColor");
            String strOptString11 = ((JSONObject) this.b).optString("BannerMPButtonTextColor");
            this.a = ((JSONObject) this.b).optBoolean("IsIabEnabled");
            String strOptString12 = ((JSONObject) this.b).optString("BannerDPDTitle");
            String strC = AbstractC3617f4.c(((JSONObject) this.b).optString("BannerDPDDescription"));
            String strOptString13 = ((JSONObject) this.b).optString("OptanonLogo");
            String strOptString14 = ((JSONObject) this.b).optString("BannerAdditionalDescription");
            this.d = ((JSONObject) this.b).optString("BannerAdditionalDescPlacement");
            q qVarJ = new com.onetrust.otpublishers.headless.UI.UIProperty.d(context).j();
            this.f = qVarJ;
            if (qVarJ != null) {
                b((c0) qVarJ.j);
                c((n) ((q) this.f).k, strOptString4, strOptString7, strOptString10);
                c((n) ((q) this.f).l, strOptString5, strOptString8, strOptString10);
                c((n) ((q) this.f).m, strOptString6, strOptString9, strOptString11);
                b bVarA = b.a();
                n nVar = bVarA.v;
                String str = (String) nVar.f;
                n nVar2 = (n) ((q) this.f).m;
                if (!com.onetrust.otpublishers.headless.Internal.a.j(str)) {
                    nVar2.f = str;
                    if (bVarA.s) {
                        nVar2.g = str;
                    }
                }
                String str2 = (String) nVar.e;
                if (!com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
                    nVar2.e = str2;
                }
                e((JSONObject) this.b);
                if (com.onetrust.otpublishers.headless.Internal.a.j((String) ((q) this.f).c)) {
                    ((q) this.f).c = strOptString;
                }
                d((m) ((q) this.f).e, strOptString2);
                d((m) ((q) this.f).g, strOptString3);
                m mVar = (m) ((q) this.f).f;
                d(mVar, strOptString12);
                String str3 = (String) mVar.g;
                mVar.c = (str3 == null || com.onetrust.otpublishers.headless.Internal.a.j(str3) || !this.a) ? 8 : 0;
                m mVar2 = (m) ((q) this.f).h;
                d(mVar2, strC);
                String str4 = (String) mVar2.g;
                mVar2.c = (str4 == null || com.onetrust.otpublishers.headless.Internal.a.j(str4) || !this.a) ? 8 : 0;
                d((m) ((q) this.f).i, strOptString14);
                com.google.android.gms.internal.appset.e eVar = (com.google.android.gms.internal.appset.e) ((q) this.f).p;
                if (com.onetrust.otpublishers.headless.Internal.a.j(eVar.h())) {
                    eVar.c = strOptString13;
                }
                com.quizlet.data.repository.user.e eVar2 = (com.quizlet.data.repository.user.e) ((q) this.f).n;
                if (com.onetrust.otpublishers.headless.Internal.a.j((String) ((m) eVar2.b).g)) {
                    ((m) eVar2.b).g = ((JSONObject) this.b).optString("BannerLinkText");
                }
            }
        } catch (JSONException e) {
            Z.p("Error while parsing Banner data, error: ", e, "OneTrust", 6);
        }
    }

    public void b(c0 c0Var) {
        com.onetrust.otpublishers.headless.UI.Helper.c cVar;
        this.e = new com.onetrust.otpublishers.headless.UI.Helper.c();
        int i = 8;
        if (!AbstractC3605e0.a((String) c0Var.e)) {
            com.onetrust.otpublishers.headless.UI.Helper.c cVar2 = (com.onetrust.otpublishers.headless.UI.Helper.c) this.e;
            cVar2.p = 8;
            cVar2.t = 8;
            return;
        }
        if (!AbstractC3605e0.a((String) c0Var.d) || com.onetrust.otpublishers.headless.Internal.a.j((String) ((n) c0Var.g).j)) {
            n nVar = new n();
            nVar.l = b.a().e;
            nVar.m = b.a().f;
            cVar = (com.onetrust.otpublishers.headless.UI.Helper.c) this.e;
            cVar.s = nVar;
            cVar.p = 0;
        } else {
            ((com.onetrust.otpublishers.headless.UI.Helper.c) this.e).j = (String) ((n) c0Var.g).j;
            String strOptString = (String) c0Var.b;
            JSONObject jSONObject = (JSONObject) this.b;
            if (strOptString == null || com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                strOptString = jSONObject != null ? jSONObject.optString("BannerLinksTextColor") : "#E8E8E8";
            }
            if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                ((com.onetrust.otpublishers.headless.UI.Helper.c) this.e).f = strOptString;
            }
            n nVar2 = (n) c0Var.g;
            nVar2.l = b.a().e;
            nVar2.m = b.a().f;
            nVar2.f = strOptString;
            cVar = (com.onetrust.otpublishers.headless.UI.Helper.c) this.e;
            cVar.s = nVar2;
            cVar.p = 8;
            i = 0;
        }
        cVar.t = i;
    }

    public void d(m mVar, String str) {
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.b)) {
            mVar.b = (String) this.c;
        }
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.g)) {
            mVar.g = str;
        }
        mVar.c = com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.g) ? 8 : mVar.c;
    }

    public void e(JSONObject jSONObject) {
        String str;
        String strOptString = jSONObject.optString("BannerIABPartnersLink");
        com.quizlet.data.repository.user.e eVar = (com.quizlet.data.repository.user.e) ((q) this.f).o;
        m mVar = (m) eVar.b;
        n nVar = new n();
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.g)) {
            mVar.g = strOptString;
        }
        nVar.j = (String) mVar.g;
        nVar.b = (AbstractC3605e0.a((String) eVar.d) && this.a) ? 0 : 8;
        b bVarA = b.a();
        n nVar2 = bVarA.u;
        String strOptString2 = (String) nVar2.f;
        if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString2)) {
            strOptString2 = (String) mVar.b;
            if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString2)) {
                strOptString2 = jSONObject.optString("BannerLinksTextColor");
            }
        }
        nVar.f = strOptString2;
        String str2 = (String) nVar2.e;
        n nVar3 = (n) ((q) this.f).m;
        if (com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
            str2 = (String) nVar3.e;
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
            nVar.e = str2;
        }
        String str3 = (String) nVar3.l;
        if (str3 != null) {
            nVar.l = str3;
        }
        String str4 = (String) nVar3.m;
        if (str4 != null) {
            nVar.m = str4;
        }
        if (bVarA.s) {
            nVar.g = strOptString2;
            str = bVarA.f;
        } else {
            str = "";
            nVar.g = "";
        }
        nVar.n = str;
        this.g = nVar;
    }

    public MatchSettingsData f(MatchSettingsData matchSettingsData) {
        Boolean[] boolArr = {Boolean.valueOf(matchSettingsData.b), Boolean.valueOf(matchSettingsData.c), Boolean.valueOf(matchSettingsData.d)};
        int i = 0;
        for (int i2 = 0; i2 < 3; i2++) {
            if (boolArr[i2].booleanValue()) {
                i++;
            }
        }
        if (i >= 2) {
            return matchSettingsData;
        }
        MatchSettingsData matchSettingsData2 = (MatchSettingsData) this.d;
        if (matchSettingsData2 == null) {
            Intrinsics.m("initialSettings");
            throw null;
        }
        return new MatchSettingsData(matchSettingsData.a, matchSettingsData2.b, matchSettingsData2.c, matchSettingsData2.d);
    }
}
