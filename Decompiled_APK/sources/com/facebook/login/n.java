package com.facebook.login;

import android.os.Bundle;
import android.text.TextUtils;
import com.facebook.FacebookException;
import com.facebook.internal.I;
import com.facebook.login.LoginClient;
import java.util.ArrayList;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class n implements I {
    public final /* synthetic */ Bundle a;
    public final /* synthetic */ GetTokenLoginMethodHandler b;
    public final /* synthetic */ LoginClient.Request c;

    public n(Bundle bundle, GetTokenLoginMethodHandler getTokenLoginMethodHandler, LoginClient.Request request) {
        this.a = bundle;
        this.b = getTokenLoginMethodHandler;
        this.c = request;
    }

    @Override // com.facebook.internal.I
    public final void b(JSONObject jSONObject) throws JSONException {
        String string;
        Bundle bundle = this.a;
        GetTokenLoginMethodHandler getTokenLoginMethodHandler = this.b;
        if (jSONObject != null) {
            try {
                string = jSONObject.getString("id");
            } catch (JSONException e) {
                LoginClient loginClientD = getTokenLoginMethodHandler.d();
                LoginClient.Request request = getTokenLoginMethodHandler.d().g;
                String message = e.getMessage();
                ArrayList arrayList = new ArrayList();
                arrayList.add("Caught exception");
                if (message != null) {
                    arrayList.add(message);
                }
                loginClientD.c(new LoginClient.Result(request, q.ERROR, null, TextUtils.join(": ", arrayList), null));
                return;
            }
        } else {
            string = null;
        }
        bundle.putString("com.facebook.platform.extra.USER_ID", string);
        getTokenLoginMethodHandler.n(this.c, bundle);
    }

    @Override // com.facebook.internal.I
    public final void c(FacebookException facebookException) {
        GetTokenLoginMethodHandler getTokenLoginMethodHandler = this.b;
        LoginClient loginClientD = getTokenLoginMethodHandler.d();
        LoginClient.Request request = getTokenLoginMethodHandler.d().g;
        String message = facebookException != null ? facebookException.getMessage() : null;
        ArrayList arrayList = new ArrayList();
        arrayList.add("Caught exception");
        if (message != null) {
            arrayList.add(message);
        }
        loginClientD.c(new LoginClient.Result(request, q.ERROR, null, TextUtils.join(": ", arrayList), null));
    }
}
