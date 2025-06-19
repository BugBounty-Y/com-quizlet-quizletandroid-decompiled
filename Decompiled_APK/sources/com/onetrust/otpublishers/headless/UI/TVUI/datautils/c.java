package com.onetrust.otpublishers.headless.UI.TVUI.datautils;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.Html;
import android.text.SpannableStringBuilder;
import androidx.camera.camera2.internal.c0;
import androidx.constraintlayout.motion.widget.n;
import androidx.navigation.internal.m;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Preferences.f;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class c {
    public static c s;
    public JSONObject a;
    public String b;
    public JSONObject c;
    public JSONObject d;
    public boolean e;
    public String f;
    public String g;
    public String h;
    public boolean i;
    public com.onetrust.otpublishers.headless.UI.UIProperty.e j;
    public String k;
    public String l;
    public String m;
    public boolean n;
    public String o;
    public String p;
    public String q;
    public com.onetrust.otpublishers.headless.UI.Helper.c r;

    public static void f(n nVar, String str, String str2, String str3) {
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
        if (bVarA.t) {
            nVar.g = str3;
            str4 = bVarA.h;
        } else {
            str4 = "";
            nVar.g = "";
        }
        nVar.n = str4;
        nVar.b = (!AbstractC3605e0.a((String) nVar.k) || com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.j)) ? 8 : 0;
        nVar.l = bVarA.g;
        nVar.m = bVarA.h;
    }

    public static boolean h(JSONObject jSONObject) {
        if (!retrofit2.adapter.rxjava3.d.l(jSONObject.optJSONArray("FirstPartyCookies"))) {
            return true;
        }
        if (jSONObject.has("SubGroups")) {
            JSONArray jSONArrayOptJSONArray = jSONObject.optJSONArray("SubGroups");
            if (!retrofit2.adapter.rxjava3.d.l(jSONArrayOptJSONArray)) {
                for (int i = 0; i < jSONArrayOptJSONArray.length(); i++) {
                    if (!retrofit2.adapter.rxjava3.d.l(jSONArrayOptJSONArray.optJSONObject(i).optJSONArray("FirstPartyCookies"))) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public static synchronized c i() {
        try {
            if (s == null) {
                c cVar = new c();
                cVar.o = "";
                cVar.p = "";
                cVar.q = "";
                s = cVar;
            }
        } catch (Throwable th) {
            throw th;
        }
        return s;
    }

    public static String j(JSONObject jSONObject) {
        return (!jSONObject.has("GroupDescriptionOTT") || com.onetrust.otpublishers.headless.Internal.a.j(jSONObject.optString("GroupDescriptionOTT")) || jSONObject.isNull("GroupDescriptionOTT")) ? jSONObject.optString("GroupDescription") : jSONObject.optString("GroupDescriptionOTT");
    }

    public static String m(JSONObject jSONObject) {
        return new SpannableStringBuilder(Html.fromHtml(jSONObject.optString("DescriptionLegal"), null, new com.onetrust.otpublishers.headless.UI.Helper.e())).toString().replace("\n\n", "\n\n• ").concat("*").replace("\n\n• *", "");
    }

    public final String a() {
        String str = this.j.a;
        return str != null ? str : "#FFFFFF";
    }

    public final String b(boolean z) {
        return z ? b.a().p : this.g;
    }

    public final JSONObject c(JSONArray jSONArray) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        JSONObject jSONObject2 = new JSONObject();
        if (jSONArray.length() > 0) {
            for (int i = 0; i < jSONArray.length(); i++) {
                try {
                    if (jSONArray.getJSONObject(i).has("SubGroups")) {
                        String strOptString = jSONArray.getJSONObject(i).optString("CustomGroupId");
                        JSONArray jSONArray2 = new JSONArray();
                        JSONArray jSONArray3 = jSONArray.getJSONObject(i).getJSONArray("SubGroups");
                        jSONObject2.put(strOptString, jSONArray.getJSONObject(i).optBoolean("ShowSubgroupToggle"));
                        for (int i2 = 0; i2 < jSONArray3.length(); i2++) {
                            jSONArray2.put(jSONArray3.getJSONObject(i2).optString("CustomGroupId"));
                            jSONObject.put(strOptString, jSONArray2);
                        }
                    }
                } catch (JSONException e) {
                    Z.p("Error in getting subgroups for a category on TV, err: ", e, "OneTrust", 6);
                }
            }
        }
        this.d = jSONObject2;
        return jSONObject;
    }

    public final void d(Context context) {
        f fVar;
        com.onetrust.otpublishers.headless.UI.UIProperty.e eVar = this.j;
        m mVar = eVar.n;
        m mVar2 = eVar.m;
        m mVar3 = eVar.p;
        m mVar4 = eVar.o;
        m mVar5 = eVar.r;
        boolean z = Boolean.parseBoolean(eVar.I);
        boolean z2 = Boolean.parseBoolean(this.j.K);
        boolean z3 = Boolean.parseBoolean(this.j.J);
        int i = 8;
        boolean z4 = false;
        int i2 = z ? 0 : 8;
        int i3 = z2 ? 0 : 8;
        if (z3 && !com.onetrust.otpublishers.headless.Internal.a.j((String) this.j.r.g)) {
            i = 0;
        }
        mVar.c = i2;
        mVar2.c = i2;
        mVar3.c = i3;
        mVar4.c = i3;
        mVar5.c = i;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z4 = true;
        } else {
            fVar = null;
        }
        if (z4) {
            sharedPreferences = fVar;
        }
        String string = sharedPreferences.getString("OTT_LAST_GIVEN_CONSENT", "0");
        if (0 == (com.onetrust.otpublishers.headless.Internal.a.j(string) ? 0L : Long.parseLong(string))) {
            mVar3.g = (String) this.j.q.g;
        }
    }

    public final void e(c0 c0Var) {
        com.onetrust.otpublishers.headless.UI.Helper.c cVar;
        this.r = new com.onetrust.otpublishers.headless.UI.Helper.c();
        int i = 8;
        if (!AbstractC3605e0.a((String) c0Var.e)) {
            com.onetrust.otpublishers.headless.UI.Helper.c cVar2 = this.r;
            cVar2.p = 8;
            cVar2.t = 8;
            return;
        }
        if (!AbstractC3605e0.a((String) c0Var.d) || com.onetrust.otpublishers.headless.Internal.a.j((String) ((n) c0Var.g).j)) {
            n nVar = new n();
            nVar.l = b.a().e;
            nVar.m = b.a().f;
            cVar = this.r;
            cVar.s = nVar;
            cVar.p = 0;
        } else {
            this.r.j = (String) ((n) c0Var.g).j;
            String strOptString = (String) c0Var.b;
            JSONObject jSONObject = this.a;
            if (strOptString == null || com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                strOptString = jSONObject != null ? jSONObject.optString("BannerLinksTextColor") : "#E8E8E8";
            }
            if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                this.r.f = strOptString;
            }
            n nVar2 = (n) c0Var.g;
            nVar2.l = b.a().e;
            nVar2.m = b.a().f;
            nVar2.f = strOptString;
            cVar = this.r;
            cVar.s = nVar2;
            cVar.p = 8;
            i = 0;
        }
        cVar.t = i;
    }

    public final void g(b bVar) {
        c0 c0Var = this.j.B;
        String str = bVar.i;
        c0Var.b = str;
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            c0Var.b = this.j.a;
        }
        String str2 = bVar.j;
        c0Var.c = str2;
        if (com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
            c0Var.b = (String) this.j.t.b;
        }
        c0Var.d = bVar.k;
        c0Var.e = bVar.l;
        c0Var.f = bVar.m;
        c0Var.g = bVar.n;
    }

    public final JSONObject k(Context context) {
        f fVar;
        JSONObject jSONObject = this.a;
        if (jSONObject != null) {
            return jSONObject;
        }
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        String string = sharedPreferences.getString("OTT_PC_DATA", null);
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return null;
        }
        return new JSONObject(string);
    }

    public final String l() {
        String str = (String) this.j.l.b;
        return str != null ? str : "#696969";
    }

    /* JADX WARN: Removed duplicated region for block: B:64:0x0227 A[Catch: JSONException -> 0x024a, TryCatch #1 {JSONException -> 0x024a, blocks: (B:62:0x0221, B:64:0x0227, B:66:0x0233, B:68:0x023f, B:72:0x024d, B:77:0x0262, B:79:0x0268, B:75:0x025a, B:61:0x021b, B:60:0x0218), top: B:84:0x0218 }] */
    /* JADX WARN: Removed duplicated region for block: B:71:0x024c  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0259  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x025a A[Catch: JSONException -> 0x024a, TryCatch #1 {JSONException -> 0x024a, blocks: (B:62:0x0221, B:64:0x0227, B:66:0x0233, B:68:0x023f, B:72:0x024d, B:77:0x0262, B:79:0x0268, B:75:0x025a, B:61:0x021b, B:60:0x0218), top: B:84:0x0218 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void n(android.content.Context r23) {
        /*
            Method dump skipped, instructions count: 676
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.n(android.content.Context):void");
    }

    public final int o(JSONObject jSONObject) {
        String strOptString = jSONObject.optString("Parent");
        JSONObject jSONObject2 = this.d;
        return (jSONObject.optString("Status").contains("always") || !((jSONObject2 == null || com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) ? true : jSONObject2.optBoolean(strOptString))) ? 8 : 0;
    }

    public final boolean p() {
        return this.e || b.a().o;
    }
}
