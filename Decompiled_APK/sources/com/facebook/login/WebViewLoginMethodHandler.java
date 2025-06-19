package com.facebook.login;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import androidx.fragment.app.I;
import com.facebook.internal.AbstractC1554i;
import com.facebook.internal.C1556k;
import com.facebook.internal.J;
import com.facebook.internal.M;
import com.facebook.internal.S;
import com.facebook.login.LoginClient;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public class WebViewLoginMethodHandler extends WebLoginMethodHandler {

    @NotNull
    public static final Parcelable.Creator<WebViewLoginMethodHandler> CREATOR = new C1565b(6);
    public S d;
    public String e;
    public final String f;
    public final com.facebook.g g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public WebViewLoginMethodHandler(LoginClient loginClient) {
        super(loginClient);
        Intrinsics.checkNotNullParameter(loginClient, "loginClient");
        Intrinsics.checkNotNullParameter(loginClient, "loginClient");
        this.f = "web_view";
        this.g = com.facebook.g.WEB_VIEW;
    }

    @Override // com.facebook.login.LoginMethodHandler
    public final void b() {
        S s = this.d;
        if (s != null) {
            if (s != null) {
                s.cancel();
            }
            this.d = null;
        }
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // com.facebook.login.LoginMethodHandler
    public final String f() {
        return this.f;
    }

    @Override // com.facebook.login.LoginMethodHandler
    public final int m(LoginClient.Request request) throws JSONException {
        Intrinsics.checkNotNullParameter(request, "request");
        Bundle parameters = n(request);
        G g = new G(this, request);
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("init", System.currentTimeMillis());
        } catch (JSONException unused) {
        }
        String string = jSONObject.toString();
        Intrinsics.checkNotNullExpressionValue(string, "e2e.toString()");
        this.e = string;
        a("e2e", string);
        I context = d().f();
        if (context == null) {
            return 0;
        }
        boolean zA = J.A(context);
        Intrinsics.checkNotNullParameter(context, "context");
        String applicationId = request.d;
        Intrinsics.checkNotNullParameter(applicationId, "applicationId");
        Intrinsics.checkNotNullParameter(parameters, "parameters");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter("oauth", "action");
        F f = new F();
        if (applicationId == null) {
            applicationId = J.t(context);
        }
        AbstractC1554i.j(applicationId, "applicationId");
        f.b = applicationId;
        f.a = context;
        f.d = parameters;
        f.e = "fbconnect://success";
        f.f = o.NATIVE_WITH_FALLBACK;
        f.g = D.FACEBOOK;
        String e2e = this.e;
        Intrinsics.e(e2e, "null cannot be cast to non-null type kotlin.String");
        Intrinsics.checkNotNullParameter(e2e, "e2e");
        Intrinsics.checkNotNullParameter(e2e, "<set-?>");
        f.j = e2e;
        f.e = zA ? "fbconnect://chrome_os_success" : "fbconnect://success";
        String authType = request.h;
        Intrinsics.checkNotNullParameter(authType, "authType");
        Intrinsics.checkNotNullParameter(authType, "<set-?>");
        f.k = authType;
        o loginBehavior = request.a;
        Intrinsics.checkNotNullParameter(loginBehavior, "loginBehavior");
        f.f = loginBehavior;
        D targetApp = request.l;
        Intrinsics.checkNotNullParameter(targetApp, "targetApp");
        f.g = targetApp;
        f.h = request.m;
        f.i = request.n;
        f.c = g;
        Bundle bundle = f.d;
        Intrinsics.e(bundle, "null cannot be cast to non-null type android.os.Bundle");
        bundle.putString("redirect_uri", f.e);
        bundle.putString("client_id", f.b);
        String str = f.j;
        if (str == null) {
            Intrinsics.m("e2e");
            throw null;
        }
        bundle.putString("e2e", str);
        bundle.putString("response_type", f.g == D.INSTAGRAM ? "token,signed_request,graph_domain,granted_scopes" : "token,signed_request,graph_domain");
        bundle.putString("return_scopes", "true");
        String str2 = f.k;
        if (str2 == null) {
            Intrinsics.m("authType");
            throw null;
        }
        bundle.putString("auth_type", str2);
        bundle.putString("login_behavior", f.f.name());
        if (f.h) {
            bundle.putString("fx_app", f.g.a);
        }
        if (f.i) {
            bundle.putString("skip_dedupe", "true");
        }
        int i = S.m;
        I context2 = f.a;
        Intrinsics.e(context2, "null cannot be cast to non-null type android.content.Context");
        D targetApp2 = f.g;
        M m = f.c;
        Intrinsics.checkNotNullParameter(context2, "context");
        Intrinsics.checkNotNullParameter(targetApp2, "targetApp");
        S.b(context2);
        this.d = new S(context2, "oauth", bundle, targetApp2, m);
        C1556k c1556k = new C1556k();
        c1556k.setRetainInstance(true);
        c1556k.q = this.d;
        c1556k.O(context.getSupportFragmentManager(), "FacebookDialogFragment");
        return 1;
    }

    @Override // com.facebook.login.WebLoginMethodHandler
    public final com.facebook.g o() {
        return this.g;
    }

    @Override // com.facebook.login.LoginMethodHandler, android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        super.writeToParcel(dest, i);
        dest.writeString(this.e);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public WebViewLoginMethodHandler(Parcel source) {
        super(source);
        Intrinsics.checkNotNullParameter(source, "source");
        this.f = "web_view";
        this.g = com.facebook.g.WEB_VIEW;
        this.e = source.readString();
    }
}
