package com.facebook.login;

import android.content.Intent;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.Log;
import com.facebook.FacebookException;
import com.facebook.FacebookRequestError;
import com.facebook.FacebookServiceException;
import com.facebook.internal.J;
import com.facebook.login.LoginClient;
import java.util.HashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public abstract class LoginMethodHandler implements Parcelable {
    public HashMap a;
    public LoginClient b;

    public LoginMethodHandler(LoginClient loginClient) {
        Intrinsics.checkNotNullParameter(loginClient, "loginClient");
        Intrinsics.checkNotNullParameter(loginClient, "<set-?>");
        this.b = loginClient;
    }

    public final void a(String str, String str2) {
        if (this.a == null) {
            this.a = new HashMap();
        }
        HashMap map = this.a;
        if (map != null) {
        }
    }

    public void b() {
    }

    public final String c(String authId) throws JSONException {
        Intrinsics.checkNotNullParameter(authId, "authId");
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("0_auth_logger_id", authId);
            jSONObject.put("3_method", f());
            l(jSONObject);
        } catch (JSONException e) {
            Log.w("LoginMethodHandler", "Error creating client state json: " + e.getMessage());
        }
        String string = jSONObject.toString();
        Intrinsics.checkNotNullExpressionValue(string, "param.toString()");
        return string;
    }

    public final LoginClient d() {
        LoginClient loginClient = this.b;
        if (loginClient != null) {
            return loginClient;
        }
        Intrinsics.m("loginClient");
        throw null;
    }

    public abstract String f();

    public String g() {
        return "fb" + com.facebook.o.b() + "://authorize/";
    }

    public final void h(String str) {
        String strB;
        LoginClient.Request request = d().g;
        if (request == null || (strB = request.d) == null) {
            strB = com.facebook.o.b();
        }
        com.facebook.appevents.p pVar = new com.facebook.appevents.p(d().f(), strB);
        Bundle bundle = new Bundle();
        bundle.putString("fb_web_login_e2e", str);
        bundle.putLong("fb_web_login_switchback_time", System.currentTimeMillis());
        bundle.putString("app_id", strB);
        com.facebook.o oVar = com.facebook.o.a;
        if (com.facebook.B.c()) {
            pVar.a.g(bundle, "fb_dialogs_web_login_dialog_complete");
        }
    }

    public boolean i(int i, int i2, Intent intent) {
        return false;
    }

    public final void j(LoginClient.Request request, Bundle values) throws Throwable {
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(values, "values");
        String authorizationCode = values.getString("code");
        if (J.D(authorizationCode)) {
            throw new FacebookException("No code param found from the request");
        }
        if (authorizationCode == null) {
            throw new FacebookException("Failed to create code exchange request");
        }
        String redirectUri = g();
        String codeVerifier = request.p;
        if (codeVerifier == null) {
            codeVerifier = "";
        }
        com.facebook.x xVar = com.facebook.x.a;
        Intrinsics.checkNotNullParameter(authorizationCode, "authorizationCode");
        Intrinsics.checkNotNullParameter(redirectUri, "redirectUri");
        Intrinsics.checkNotNullParameter(codeVerifier, "codeVerifier");
        Bundle bundle = new Bundle();
        bundle.putString("code", authorizationCode);
        bundle.putString("client_id", com.facebook.o.b());
        bundle.putString("redirect_uri", redirectUri);
        bundle.putString("code_verifier", codeVerifier);
        String str = com.facebook.t.j;
        com.facebook.t tVarQ = assistantMode.utils.studiableMetadata.b.Q(null, "oauth/access_token", null);
        tVarQ.h = xVar;
        Intrinsics.checkNotNullParameter(bundle, "<set-?>");
        tVarQ.d = bundle;
        com.facebook.w wVarC = tVarQ.c();
        FacebookRequestError facebookRequestError = wVarC.c;
        if (facebookRequestError != null) {
            throw new FacebookServiceException(facebookRequestError, facebookRequestError.a());
        }
        try {
            JSONObject jSONObject = wVarC.b;
            String string = jSONObject != null ? jSONObject.getString("access_token") : null;
            if (jSONObject == null || J.D(string)) {
                throw new FacebookException("No access token found from result");
            }
            values.putString("access_token", string);
            if (jSONObject.has("id_token")) {
                values.putString("id_token", jSONObject.getString("id_token"));
            }
        } catch (JSONException e) {
            throw new FacebookException("Fail to process code exchange response: " + e.getMessage());
        }
    }

    public void l(JSONObject param) {
        Intrinsics.checkNotNullParameter(param, "param");
    }

    public abstract int m(LoginClient.Request request);

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i) {
        Intrinsics.checkNotNullParameter(parcel, "dest");
        HashMap map = this.a;
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        if (map == null) {
            parcel.writeInt(-1);
            return;
        }
        parcel.writeInt(map.size());
        for (Map.Entry entry : map.entrySet()) {
            String str = (String) entry.getKey();
            String str2 = (String) entry.getValue();
            parcel.writeString(str);
            parcel.writeString(str2);
        }
    }

    public LoginMethodHandler(Parcel parcel) {
        HashMap map;
        Intrinsics.checkNotNullParameter(parcel, "source");
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        int i = parcel.readInt();
        if (i < 0) {
            map = null;
        } else {
            map = new HashMap();
            for (int i2 = 0; i2 < i; i2++) {
                map.put(parcel.readString(), parcel.readString());
            }
        }
        this.a = map != null ? V.m(map) : null;
    }
}
