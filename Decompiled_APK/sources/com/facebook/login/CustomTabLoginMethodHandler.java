package com.facebook.login;

import android.content.Intent;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import androidx.fragment.app.I;
import com.facebook.CustomTabMainActivity;
import com.facebook.internal.AbstractC1554i;
import com.facebook.internal.J;
import com.facebook.login.LoginClient;
import com.google.android.gms.internal.mlkit_vision_common.I2;
import java.math.BigInteger;
import java.util.Random;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class CustomTabLoginMethodHandler extends WebLoginMethodHandler {

    @NotNull
    public static final Parcelable.Creator<CustomTabLoginMethodHandler> CREATOR = new C1565b(0);
    public static boolean i;
    public String d;
    public final String e;
    public final String f;
    public final String g;
    public final com.facebook.g h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public CustomTabLoginMethodHandler(LoginClient loginClient) {
        super(loginClient);
        Intrinsics.checkNotNullParameter(loginClient, "loginClient");
        Intrinsics.checkNotNullParameter(loginClient, "loginClient");
        this.g = "custom_tab";
        this.h = com.facebook.g.CHROME_CUSTOM_TAB;
        String string = new BigInteger(100, new Random()).toString(32);
        Intrinsics.checkNotNullExpressionValue(string, "BigInteger(length * 5, r).toString(32)");
        this.e = string;
        i = false;
        this.f = AbstractC1554i.e(super.g());
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // com.facebook.login.LoginMethodHandler
    public final String f() {
        return this.g;
    }

    @Override // com.facebook.login.LoginMethodHandler
    public final String g() {
        return this.f;
    }

    /* JADX WARN: Removed duplicated region for block: B:52:0x00d9  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x000e  */
    @Override // com.facebook.login.LoginMethodHandler
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean i(int r7, int r8, android.content.Intent r9) throws java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 280
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.login.CustomTabLoginMethodHandler.i(int, int, android.content.Intent):boolean");
    }

    @Override // com.facebook.login.LoginMethodHandler
    public final void l(JSONObject param) throws JSONException {
        Intrinsics.checkNotNullParameter(param, "param");
        param.put("7_challenge", this.e);
    }

    @Override // com.facebook.login.LoginMethodHandler
    public final int m(LoginClient.Request request) throws Exception {
        String str = this.f;
        Intrinsics.checkNotNullParameter(request, "request");
        LoginClient loginClientD = d();
        if (str.length() != 0) {
            Bundle parameters = n(request);
            Intrinsics.checkNotNullParameter(parameters, "parameters");
            Intrinsics.checkNotNullParameter(request, "request");
            parameters.putString("redirect_uri", str);
            D d = D.INSTAGRAM;
            D d2 = request.l;
            boolean z = d2 == d;
            String str2 = request.d;
            if (z) {
                parameters.putString("app_id", str2);
            } else {
                parameters.putString("client_id", str2);
            }
            JSONObject jSONObject = new JSONObject();
            try {
                jSONObject.put("init", System.currentTimeMillis());
            } catch (JSONException unused) {
            }
            String string = jSONObject.toString();
            Intrinsics.checkNotNullExpressionValue(string, "e2e.toString()");
            parameters.putString("e2e", string);
            if (d2 == d) {
                parameters.putString("response_type", "token,signed_request,graph_domain,granted_scopes");
            } else {
                if (request.b.contains("openid")) {
                    parameters.putString("nonce", request.o);
                }
                parameters.putString("response_type", "id_token,token,signed_request,graph_domain");
            }
            parameters.putString("code_challenge", request.q);
            EnumC1564a enumC1564a = request.r;
            parameters.putString("code_challenge_method", enumC1564a != null ? enumC1564a.name() : null);
            parameters.putString("return_scopes", "true");
            parameters.putString("auth_type", request.h);
            parameters.putString("login_behavior", request.a.name());
            com.facebook.o oVar = com.facebook.o.a;
            parameters.putString("sdk", "android-18.0.3");
            parameters.putString("sso", "chrome_custom_tab");
            parameters.putString("cct_prefetching", com.facebook.o.l ? "1" : "0");
            if (request.m) {
                parameters.putString("fx_app", d2.a);
            }
            if (request.n) {
                parameters.putString("skip_dedupe", "true");
            }
            String str3 = request.j;
            if (str3 != null) {
                parameters.putString("messenger_page_id", str3);
                parameters.putString("reset_messenger_state", request.k ? "1" : "0");
            }
            if (i) {
                parameters.putString("cct_over_app_switch", "1");
            }
            if (com.facebook.o.l) {
                if (d2 == d) {
                    androidx.browser.customtabs.l lVar = C1566c.b;
                    Intrinsics.checkNotNullParameter("oauth", "action");
                    I2.f(J.a(J.r(), "oauth/authorize", parameters));
                } else {
                    androidx.browser.customtabs.l lVar2 = C1566c.b;
                    Intrinsics.checkNotNullParameter("oauth", "action");
                    I2.f(J.a(J.p(), com.facebook.o.d() + "/dialog/oauth", parameters));
                }
            }
            I iF = loginClientD.f();
            if (iF != null) {
                Intent intent = new Intent(iF, (Class<?>) CustomTabMainActivity.class);
                int i2 = CustomTabMainActivity.c;
                intent.putExtra("CustomTabMainActivity.extra_action", "oauth");
                intent.putExtra("CustomTabMainActivity.extra_params", parameters);
                String strC = this.d;
                if (strC == null) {
                    strC = AbstractC1554i.c();
                    this.d = strC;
                }
                intent.putExtra("CustomTabMainActivity.extra_chromePackage", strC);
                intent.putExtra("CustomTabMainActivity.extra_targetApp", d2.a);
                u uVar = loginClientD.c;
                if (uVar != null) {
                    uVar.startActivityForResult(intent, 1);
                }
                return 1;
            }
        }
        return 0;
    }

    @Override // com.facebook.login.WebLoginMethodHandler
    public final com.facebook.g o() {
        return this.h;
    }

    @Override // com.facebook.login.LoginMethodHandler, android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i2) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        super.writeToParcel(dest, i2);
        dest.writeString(this.e);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public CustomTabLoginMethodHandler(Parcel source) {
        super(source);
        Intrinsics.checkNotNullParameter(source, "source");
        this.g = "custom_tab";
        this.h = com.facebook.g.CHROME_CUSTOM_TAB;
        this.e = source.readString();
        this.f = AbstractC1554i.e(super.g());
    }
}
