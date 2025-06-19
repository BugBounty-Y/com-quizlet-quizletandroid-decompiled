package com.onetrust.otpublishers.headless.UI.mobiledatautils;

import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.widget.TextView;
import androidx.camera.camera2.internal.c0;
import androidx.constraintlayout.motion.widget.n;
import androidx.navigation.internal.m;
import androidx.room.s;
import com.airbnb.lottie.parser.l;
import com.google.android.gms.cloudmessaging.k;
import com.google.android.gms.internal.ads.Gj;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Preferences.f;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.UI.UIProperty.e;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class b {
    public String A;
    public m B;
    public m C;
    public m D;
    public m E;
    public m F;
    public String G;
    public String H;
    public boolean J;
    public String M;
    public String N;
    public com.onetrust.otpublishers.headless.UI.Helper.c a;
    public com.onetrust.otpublishers.headless.UI.Helper.c b;
    public l c;
    public JSONObject d;
    public com.onetrust.otpublishers.headless.UI.Helper.c e;
    public com.onetrust.otpublishers.headless.UI.Helper.c f;
    public com.onetrust.otpublishers.headless.UI.Helper.c g;
    public com.onetrust.otpublishers.headless.UI.Helper.c h;
    public com.onetrust.otpublishers.headless.UI.Helper.c i;
    public com.onetrust.otpublishers.headless.UI.Helper.c j;
    public com.onetrust.otpublishers.headless.UI.Helper.c k;
    public com.onetrust.otpublishers.headless.UI.Helper.c l;
    public com.onetrust.otpublishers.headless.UI.Helper.c m;
    public com.onetrust.otpublishers.headless.UI.Helper.c n;
    public boolean o;
    public String q;
    public String r;
    public String s;
    public String t;
    public e u;
    public s v;
    public com.onetrust.otpublishers.headless.UI.Helper.c w;
    public com.onetrust.otpublishers.headless.UI.Helper.c x;
    public com.onetrust.otpublishers.headless.UI.Helper.c y;
    public String z;
    public JSONArray p = new JSONArray();
    public String I = "";
    public boolean K = true;
    public boolean L = false;

    /* JADX WARN: Removed duplicated region for block: B:24:0x0082  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x008e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void b(android.widget.TextView r1, androidx.navigation.internal.m r2, com.onetrust.otpublishers.headless.UI.Helper.c r3, com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration r4) {
        /*
            java.lang.String r0 = r3.b()
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r0)
            if (r0 != 0) goto L16
            java.lang.String r0 = r3.b()
            int r0 = android.graphics.Color.parseColor(r0)
            r1.setTextColor(r0)
            goto L2b
        L16:
            java.io.Serializable r0 = r2.b
            java.lang.String r0 = (java.lang.String) r0
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r0)
            if (r0 != 0) goto L2b
            java.io.Serializable r0 = r2.b
            java.lang.String r0 = (java.lang.String) r0
            int r0 = android.graphics.Color.parseColor(r0)
            r1.setTextColor(r0)
        L2b:
            java.lang.String r0 = r3.q
            assistantMode.utils.studiableMetadata.b.x(r1, r0)
            java.lang.String r0 = r3.r
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r0)
            if (r0 != 0) goto L3b
            java.lang.String r2 = r3.r
            goto L51
        L3b:
            java.lang.Object r0 = r2.d
            com.google.android.gms.cloudmessaging.k r0 = (com.google.android.gms.cloudmessaging.k) r0
            java.lang.Object r0 = r0.d
            java.lang.String r0 = (java.lang.String) r0
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r0)
            if (r0 != 0) goto L58
            java.lang.Object r2 = r2.d
            com.google.android.gms.cloudmessaging.k r2 = (com.google.android.gms.cloudmessaging.k) r2
            java.lang.Object r2 = r2.d
            java.lang.String r2 = (java.lang.String) r2
        L51:
            float r2 = java.lang.Float.parseFloat(r2)
            r1.setTextSize(r2)
        L58:
            java.lang.Object r2 = r3.d
            com.google.android.gms.cloudmessaging.k r2 = (com.google.android.gms.cloudmessaging.k) r2
            java.lang.Object r3 = r2.e
            java.lang.String r3 = (java.lang.String) r3
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r3)
            if (r0 != 0) goto L72
            if (r4 == 0) goto L72
            android.graphics.Typeface r3 = r4.getOtTypeFaceMap(r3)
            if (r3 == 0) goto L72
            r1.setTypeface(r3)
            return
        L72:
            int r3 = r2.b
            int r3 = com.google.android.gms.cloudmessaging.k.a(r1, r3)
            java.lang.Object r4 = r2.c
            java.lang.String r4 = (java.lang.String) r4
            boolean r4 = com.onetrust.otpublishers.headless.Internal.a.j(r4)
            if (r4 != 0) goto L8e
            java.lang.Object r2 = r2.c
            java.lang.String r2 = (java.lang.String) r2
            android.graphics.Typeface r2 = android.graphics.Typeface.create(r2, r3)
        L8a:
            r1.setTypeface(r2)
            return
        L8e:
            android.graphics.Typeface r2 = r1.getTypeface()
            android.graphics.Typeface r2 = android.graphics.Typeface.create(r2, r3)
            goto L8a
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.mobiledatautils.b.b(android.widget.TextView, androidx.navigation.internal.m, com.onetrust.otpublishers.headless.UI.Helper.c, com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration):void");
    }

    public static void h(e eVar, JSONObject jSONObject) {
        m mVar = eVar.k;
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.g) && !com.onetrust.otpublishers.headless.Internal.a.j(jSONObject.optString("MainText"))) {
            mVar.g = jSONObject.optString("MainText");
            mVar.e = String.valueOf(true);
            eVar.k = mVar;
        }
        m mVar2 = eVar.l;
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar2.g) && !com.onetrust.otpublishers.headless.Internal.a.j(jSONObject.optString("MainInfoText"))) {
            mVar2.g = jSONObject.optString("MainInfoText");
            mVar2.e = String.valueOf(true);
            eVar.l = mVar2;
        }
        com.google.android.gms.internal.appset.e eVar2 = eVar.A;
        if (com.onetrust.otpublishers.headless.Internal.a.j(eVar2.h()) && !com.onetrust.otpublishers.headless.Internal.a.j(jSONObject.optString("OptanonLogo"))) {
            eVar2.c = jSONObject.optString("OptanonLogo");
            eVar.A = eVar2;
        }
        com.quizlet.data.repository.user.e eVar3 = eVar.D;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(jSONObject.optString("AboutText")) && com.onetrust.otpublishers.headless.Internal.a.j((String) ((m) eVar3.b).g)) {
            ((m) eVar3.b).g = jSONObject.optString("AboutText");
            ((m) eVar3.b).e = String.valueOf(true);
            if (com.onetrust.otpublishers.headless.Internal.a.j((String) eVar3.c)) {
                eVar3.c = jSONObject.optString("AboutLink");
            }
            eVar.D = eVar3;
        }
        eVar.v.e = String.valueOf(true);
        com.quizlet.data.repository.user.e eVar4 = eVar.E;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(jSONObject.optString("PCenterVendorsListText")) && com.onetrust.otpublishers.headless.Internal.a.j((String) ((m) eVar4.b).g)) {
            ((m) eVar4.b).g = jSONObject.optString("PCenterVendorsListText");
            ((m) eVar4.b).e = String.valueOf(true);
            eVar.E = eVar4;
        }
        m mVar3 = eVar.s;
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar3.g) && !com.onetrust.otpublishers.headless.Internal.a.j(jSONObject.optString("PreferenceCenterManagePreferencesText"))) {
            mVar3.g = jSONObject.optString("PreferenceCenterManagePreferencesText");
        }
        mVar3.e = String.valueOf(true);
        eVar.s = mVar3;
        n nVar = eVar.w;
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.j)) {
            nVar.j = jSONObject.optString("ConfirmText", "");
            nVar.k = com.onetrust.otpublishers.headless.Internal.a.j(jSONObject.optString("ConfirmText", "")) ? String.valueOf(false) : String.valueOf(true);
            eVar.w = nVar;
        }
        n nVar2 = eVar.x;
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) nVar2.j)) {
            nVar2.j = jSONObject.optString("PCenterRejectAllButtonText", "");
            nVar2.k = (!jSONObject.optBoolean("PCenterShowRejectAllButton") || com.onetrust.otpublishers.headless.Internal.a.j(jSONObject.optString("PCenterRejectAllButtonText", ""))) ? String.valueOf(false) : String.valueOf(true);
            eVar.x = nVar2;
        }
        n nVar3 = eVar.y;
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) nVar3.j)) {
            nVar3.j = jSONObject.optString("PreferenceCenterConfirmText", "");
        }
        nVar3.k = String.valueOf(true);
        eVar.y = nVar3;
    }

    public final void a(Context context) {
        f fVar;
        boolean z;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(this.u.I) && "true".equals(this.u.I)) {
            e eVar = this.u;
            this.z = eVar.I;
            if (!com.onetrust.otpublishers.headless.Internal.a.j(eVar.J) && "true".equals(this.u.J)) {
                e eVar2 = this.u;
                this.A = eVar2.J;
                this.C = Gj.c(this.d, eVar2.r, "", false);
            }
            this.D = Gj.c(this.d, this.u.n, "", false);
            this.B = Gj.c(this.d, this.u.m, "", false);
            this.J = this.u.L;
        }
        if (com.onetrust.otpublishers.headless.Internal.a.j(this.u.K) || !"true".equals(this.u.K)) {
            return;
        }
        this.G = this.u.K;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
            z = false;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        String string = sharedPreferences.getString("OTT_LAST_GIVEN_CONSENT", "0");
        this.E = Gj.c(this.d, (com.onetrust.otpublishers.headless.Internal.a.j(string) ? 0L : Long.parseLong(string)) != 0 ? this.u.p : this.u.q, "", false);
        this.F = Gj.c(this.d, this.u.o, "", false);
    }

    public final void c(TextView textView, OTConfiguration oTConfiguration) {
        Typeface otTypeFaceMap;
        e eVar = this.u;
        if (eVar == null || !eVar.i) {
            textView.setVisibility(8);
            return;
        }
        textView.setVisibility(0);
        m mVar = this.u.l;
        textView.setTextColor(Color.parseColor((String) mVar.b));
        String str = (String) ((k) mVar.d).d;
        if (str != null) {
            textView.setTextSize(Float.parseFloat(str));
        }
        k kVar = (k) mVar.d;
        String str2 = (String) kVar.e;
        if (com.onetrust.otpublishers.headless.Internal.a.j(str2) || oTConfiguration == null || (otTypeFaceMap = oTConfiguration.getOtTypeFaceMap(str2)) == null) {
            int iA = k.a(textView, kVar.b);
            textView.setTypeface(!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.c) ? Typeface.create((String) kVar.c, iA) : Typeface.create(textView.getTypeface(), iA));
        } else {
            textView.setTypeface(otTypeFaceMap);
        }
        if (P.k(textView.getContext())) {
            textView.setTextAlignment(6);
        } else {
            textView.setTextAlignment(4);
        }
    }

    public final void d(c0 c0Var, com.onetrust.otpublishers.headless.UI.Helper.c cVar, s sVar) {
        if (!AbstractC3605e0.a((String) c0Var.e)) {
            cVar.p = 8;
            cVar.t = 8;
            cVar.u = 8;
            return;
        }
        if (!AbstractC3605e0.a((String) c0Var.d) || com.onetrust.otpublishers.headless.Internal.a.j((String) ((n) c0Var.g).j)) {
            String strC = this.c.c((String) c0Var.f, this.d.optString("PcTextColor"), "#FFFFFF", "#696969");
            cVar.p = 0;
            cVar.t = 8;
            cVar.u = 8;
            cVar.f = strC;
            cVar.j = this.d.optString("CloseText");
            return;
        }
        if (AbstractC3605e0.a((String) ((n) c0Var.g).k)) {
            cVar.u = 0;
            cVar.t = 8;
            cVar.p = 8;
            String str = (String) c0Var.b;
            n nVar = (n) c0Var.g;
            k kVar = (k) nVar.d;
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.d)) {
                cVar.r = (String) kVar.d;
            }
            cVar.d = kVar;
            String str2 = (String) nVar.f;
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
                str = str2;
            }
            cVar.f = this.c.c(str, this.d.optString("PcTextColor"), "#696969", "#FFFFFF");
            cVar.e = (String) nVar.e;
            cVar.s = nVar;
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.g)) {
                cVar.g = (String) nVar.g;
            }
        } else {
            l lVar = this.c;
            String strOptString = (String) c0Var.b;
            JSONObject jSONObject = this.d;
            lVar.getClass();
            if (strOptString == null || com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                strOptString = jSONObject != null ? jSONObject.optString("PcTextColor") : "#E8E8E8";
            }
            if (sVar != null && !com.onetrust.otpublishers.headless.Internal.a.j(sVar.b)) {
                strOptString = sVar.b;
            }
            if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                cVar.f = strOptString;
            }
            cVar.t = 0;
            cVar.u = 8;
            cVar.p = 8;
        }
        cVar.j = (String) ((n) c0Var.g).j;
    }

    public final void e(n nVar, com.onetrust.otpublishers.headless.UI.Helper.c cVar) {
        k kVar = (k) nVar.d;
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.d)) {
            cVar.r = (String) kVar.d;
        }
        cVar.d = kVar;
        String strC = this.c.c((String) nVar.f, this.d.optString("PcButtonTextColor"), "#FFFFFF", "#FFFFFF");
        String strC2 = this.c.c((String) nVar.e, this.d.optString("PcButtonColor"), "#6CC04A", "#80BE5A");
        if (cVar == this.m) {
            strC = this.c.c((String) nVar.f, this.d.optString("PcButtonTextColor"), "#FFFFFF", "#80BE5A");
            strC2 = this.c.c((String) nVar.e, this.d.optString("PcButtonColor"), "#6CC04A", "#FFFFFF");
        }
        cVar.f = strC;
        cVar.e = strC2;
        cVar.s = nVar;
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.g)) {
            cVar.g = (String) nVar.g;
        }
        cVar.j = (String) nVar.j;
        if (cVar == this.m) {
            cVar.p = 0;
        } else {
            cVar.p = ((String) nVar.k).equals(String.valueOf(true)) ? 0 : 8;
        }
    }

    public final void f(m mVar, m mVar2, com.onetrust.otpublishers.headless.UI.Helper.c cVar) {
        if (cVar == this.g && !this.d.optBoolean("IsIabEnabled") && "".equals(this.d.optString("IabType"))) {
            cVar.p = 8;
        }
        if (cVar == this.h) {
            cVar.p = mVar.c;
        }
        cVar.j = (String) mVar.g;
        cVar.f = this.c.c((String) mVar2.b, this.d.optString("PcTextColor"), "#696969", "#FFFFFF");
        l lVar = this.c;
        String strValueOf = (String) mVar2.f;
        lVar.getClass();
        if (com.onetrust.otpublishers.headless.Internal.a.j(strValueOf)) {
            strValueOf = String.valueOf(2);
        }
        cVar.q = strValueOf;
        k kVar = (k) mVar2.d;
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.d)) {
            cVar.r = (String) kVar.d;
        }
        cVar.d = kVar;
    }

    public final void g(m mVar, com.onetrust.otpublishers.headless.UI.Helper.c cVar, String str) {
        String strValueOf;
        if (cVar == this.w) {
            String strOptString = com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.g) ? this.d.optString("AlwaysActiveText", "") : (String) mVar.g;
            cVar.f = this.c.c((String) mVar.b, this.d.optString(str), "#3860BE", "#3860BE");
            cVar.j = strOptString;
        } else {
            cVar.f = this.c.c((String) mVar.b, this.d.optString(str), "#696969", "#FFFFFF");
            cVar.p = 0;
        }
        if (cVar == this.w && com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.f)) {
            strValueOf = "6";
        } else {
            l lVar = this.c;
            String str2 = (String) mVar.f;
            lVar.getClass();
            strValueOf = !com.onetrust.otpublishers.headless.Internal.a.j(str2) ? str2 : String.valueOf(2);
        }
        cVar.q = strValueOf;
        k kVar = (k) mVar.d;
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.d)) {
            cVar.r = (String) kVar.d;
        }
        cVar.d = kVar;
    }

    public final void i(JSONObject jSONObject) {
        this.u.z.c = jSONObject.optString("CloseText");
        this.u.A.d = jSONObject.optString("PCLogoScreenReader");
        this.u.G.b = jSONObject.optString("PCDSIDCopyAriaLabel");
        this.u.D.e = jSONObject.optString("PCPrivacyLinkActionAriaLabel");
    }

    public final boolean j(int i, Context context, OTPublishersHeadlessSDK oTPublishersHeadlessSDK) throws JSONException {
        try {
            JSONObject preferenceCenterData = oTPublishersHeadlessSDK.getPreferenceCenterData();
            this.d = preferenceCenterData;
            int i2 = 0;
            if (preferenceCenterData == null) {
                return false;
            }
            this.c = new l(i, 13);
            assistantMode.utils.studiableMetadata.b.D(preferenceCenterData, false);
            com.onetrust.otpublishers.headless.UI.UIProperty.f fVar = new com.onetrust.otpublishers.headless.UI.UIProperty.f(context);
            e eVarC = fVar.c(i);
            this.u = eVarC;
            h(eVarC, this.d);
            this.u = eVarC;
            this.v = fVar.a.c();
            this.a = new com.onetrust.otpublishers.headless.UI.Helper.c();
            this.b = new com.onetrust.otpublishers.headless.UI.Helper.c();
            this.e = new com.onetrust.otpublishers.headless.UI.Helper.c();
            this.f = new com.onetrust.otpublishers.headless.UI.Helper.c();
            this.g = new com.onetrust.otpublishers.headless.UI.Helper.c();
            this.h = new com.onetrust.otpublishers.headless.UI.Helper.c();
            this.i = new com.onetrust.otpublishers.headless.UI.Helper.c();
            this.j = new com.onetrust.otpublishers.headless.UI.Helper.c();
            this.k = new com.onetrust.otpublishers.headless.UI.Helper.c();
            this.l = new com.onetrust.otpublishers.headless.UI.Helper.c();
            this.m = new com.onetrust.otpublishers.headless.UI.Helper.c();
            this.n = new com.onetrust.otpublishers.headless.UI.Helper.c();
            this.w = new com.onetrust.otpublishers.headless.UI.Helper.c();
            this.x = new com.onetrust.otpublishers.headless.UI.Helper.c();
            this.y = new com.onetrust.otpublishers.headless.UI.Helper.c();
            this.I = this.d.optString("BConsentText");
            k(this.u.k, this.a, "PcTextColor");
            k(this.u.l, this.b, "PcTextColor");
            com.quizlet.data.repository.user.e eVar = this.u.D;
            String string = this.d.getString("PcLinksTextColor");
            com.onetrust.otpublishers.headless.UI.Helper.c cVar = this.e;
            m mVar = (m) eVar.b;
            k(mVar, cVar, "PcLinksTextColor");
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.b)) {
                string = (String) mVar.b;
            }
            cVar.f = string;
            cVar.p = AbstractC3605e0.a((String) eVar.d) ? 0 : 8;
            k(this.u.v, this.f, "PcTextColor");
            e eVar2 = this.u;
            f((m) eVar2.E.b, eVar2.t, this.g);
            e eVar3 = this.u;
            f((m) eVar3.F.b, eVar3.t, this.h);
            com.google.android.gms.internal.appset.e eVar4 = this.u.A;
            com.onetrust.otpublishers.headless.UI.Helper.c cVar2 = this.i;
            cVar2.j = (eVar4.h() == null || eVar4.h().equals("")) ? null : eVar4.h();
            if (!eVar4.i()) {
                i2 = 8;
            }
            cVar2.p = i2;
            k(this.u.s, this.j, "PcTextColor");
            e(this.u.w, this.k);
            e(this.u.x, this.l);
            e(this.u.y, this.m);
            if (this.d.has("LegIntSettings") && !this.d.isNull("LegIntSettings")) {
                this.o = this.d.getJSONObject("LegIntSettings").getBoolean("PAllowLI");
            }
            this.p = P.g(this.d);
            e eVar5 = this.u;
            this.q = (String) eVar5.D.c;
            this.r = this.c.c(eVar5.a, this.d.optString("PcBackgroundColor"), "#FFFFFF", "#2F2F2F");
            l lVar = this.c;
            String strOptString = this.u.g;
            JSONObject jSONObject = this.d;
            lVar.getClass();
            if (strOptString == null || com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                strOptString = jSONObject != null ? jSONObject.optString("PcTextColor") : "#E8E8E8";
            }
            this.s = strOptString;
            l lVar2 = this.c;
            JSONObject jSONObject2 = this.d;
            lVar2.getClass();
            if (com.onetrust.otpublishers.headless.Internal.a.j("") && jSONObject2 != null) {
                jSONObject2.optString("PcTextColor");
            }
            this.t = this.c.c(this.u.b, "", "#E8E8E8", "#555555");
            e eVar6 = this.u;
            this.H = eVar6.h;
            d(eVar6.z, this.n, this.v);
            g(this.u.u, this.w, "PcLinksTextColor");
            g(this.u.t, this.x, "PcTextColor");
            g(this.u.l, this.y, "PcTextColor");
            a(context);
            i(this.d);
            this.K = this.u.j;
            this.L = this.d.optBoolean("IsIabEnabled");
            this.M = this.d.optString("IabType");
            this.N = this.d.optString("PCIllusText");
            return true;
        } catch (JSONException e) {
            Z.p("Error in ui property object, error message = ", e, "PC Config", 6);
            return true;
        }
    }

    public final void k(m mVar, com.onetrust.otpublishers.headless.UI.Helper.c cVar, String str) {
        if (!mVar.a() || com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.g)) {
            cVar.p = 8;
            return;
        }
        cVar.j = (String) mVar.g;
        cVar.p = 0;
        String strC = this.c.c((String) mVar.b, this.d.optString(str), "#696969", "#FFFFFF");
        if (cVar == this.e) {
            strC = this.c.c((String) mVar.b, this.d.optString(str), "#3860BE", "#3860BE");
        }
        cVar.f = strC;
        l lVar = this.c;
        String strValueOf = (String) mVar.f;
        lVar.getClass();
        if (com.onetrust.otpublishers.headless.Internal.a.j(strValueOf)) {
            strValueOf = String.valueOf(2);
        }
        cVar.q = strValueOf;
        k kVar = (k) mVar.d;
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.d)) {
            cVar.r = (String) kVar.d;
        }
        cVar.d = kVar;
    }
}
