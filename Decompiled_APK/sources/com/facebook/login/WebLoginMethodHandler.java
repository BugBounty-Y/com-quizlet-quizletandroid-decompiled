package com.facebook.login;

import android.content.Context;
import android.os.Bundle;
import android.os.Parcel;
import android.text.TextUtils;
import android.webkit.CookieSyncManager;
import com.facebook.AccessToken;
import com.facebook.FacebookException;
import com.facebook.FacebookOperationCanceledException;
import com.facebook.FacebookRequestError;
import com.facebook.FacebookServiceException;
import com.facebook.internal.J;
import com.facebook.login.LoginClient;
import com.google.android.gms.internal.mlkit_vision_common.J2;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public abstract class WebLoginMethodHandler extends LoginMethodHandler {
    public String c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public WebLoginMethodHandler(Parcel source) {
        super(source);
        Intrinsics.checkNotNullParameter(source, "source");
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x0080  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.os.Bundle n(com.facebook.login.LoginClient.Request r8) {
        /*
            r7 = this;
            java.lang.String r0 = "request"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r0)
            android.os.Bundle r0 = new android.os.Bundle
            r0.<init>()
            java.util.Set r1 = r8.b
            java.util.Collection r1 = (java.util.Collection) r1
            if (r1 == 0) goto L29
            boolean r1 = r1.isEmpty()
            if (r1 == 0) goto L17
            goto L29
        L17:
            java.util.Set r1 = r8.b
            java.lang.Iterable r1 = (java.lang.Iterable) r1
            java.lang.String r2 = ","
            java.lang.String r1 = android.text.TextUtils.join(r2, r1)
            java.lang.String r2 = "scope"
            r0.putString(r2, r1)
            r7.a(r2, r1)
        L29:
            com.facebook.login.d r1 = r8.c
            if (r1 != 0) goto L2f
            com.facebook.login.d r1 = com.facebook.login.EnumC1567d.NONE
        L2f:
            java.lang.String r2 = "default_audience"
            java.lang.String r1 = r1.a
            r0.putString(r2, r1)
            java.lang.String r8 = r8.e
            java.lang.String r8 = r7.c(r8)
            java.lang.String r1 = "state"
            r0.putString(r1, r8)
            java.util.Date r8 = com.facebook.AccessToken.l
            com.facebook.AccessToken r8 = com.google.android.gms.internal.mlkit_vision_common.D.c()
            if (r8 == 0) goto L4c
            java.lang.String r8 = r8.e
            goto L4d
        L4c:
            r8 = 0
        L4d:
            java.lang.String r1 = "0"
            java.lang.String r2 = "1"
            java.lang.String r3 = "access_token"
            if (r8 == 0) goto L80
            com.facebook.login.LoginClient r4 = r7.d()
            androidx.fragment.app.I r4 = r4.f()
            if (r4 == 0) goto L60
            goto L64
        L60:
            android.content.Context r4 = com.facebook.o.a()
        L64:
            java.lang.String r5 = "com.facebook.login.AuthorizationClient.WebViewAuthHandler.TOKEN_STORE_KEY"
            r6 = 0
            android.content.SharedPreferences r4 = r4.getSharedPreferences(r5, r6)
            java.lang.String r5 = "TOKEN"
            java.lang.String r6 = ""
            java.lang.String r4 = r4.getString(r5, r6)
            boolean r4 = r8.equals(r4)
            if (r4 == 0) goto L80
            r0.putString(r3, r8)
            r7.a(r3, r2)
            goto L90
        L80:
            com.facebook.login.LoginClient r8 = r7.d()
            androidx.fragment.app.I r8 = r8.f()
            if (r8 == 0) goto L8d
            com.facebook.internal.J.c(r8)
        L8d:
            r7.a(r3, r1)
        L90:
            long r3 = java.lang.System.currentTimeMillis()
            java.lang.String r8 = java.lang.String.valueOf(r3)
            java.lang.String r3 = "cbt"
            r0.putString(r3, r8)
            com.facebook.o r8 = com.facebook.o.a
            boolean r8 = com.facebook.B.c()
            if (r8 == 0) goto La6
            r1 = r2
        La6:
            java.lang.String r8 = "ies"
            r0.putString(r8, r1)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.login.WebLoginMethodHandler.n(com.facebook.login.LoginClient$Request):android.os.Bundle");
    }

    public abstract com.facebook.g o();

    public final void p(LoginClient.Request request, Bundle bundle, FacebookException facebookException) {
        LoginClient.Result result;
        LoginClient.Result result2;
        Intrinsics.checkNotNullParameter(request, "request");
        LoginClient loginClientD = d();
        String strValueOf = null;
        this.c = null;
        q qVar = q.ERROR;
        if (bundle != null) {
            if (bundle.containsKey("e2e")) {
                this.c = bundle.getString("e2e");
            }
            try {
                AccessToken accessTokenC = J2.c(request.b, bundle, o(), request.d);
                result2 = new LoginClient.Result(loginClientD.g, q.SUCCESS, accessTokenC, J2.d(bundle, request.o), null, null);
                if (loginClientD.f() != null) {
                    try {
                        CookieSyncManager.createInstance(loginClientD.f()).sync();
                    } catch (Exception unused) {
                    }
                    if (accessTokenC != null) {
                        String str = accessTokenC.e;
                        Context contextF = d().f();
                        if (contextF == null) {
                            contextF = com.facebook.o.a();
                        }
                        contextF.getSharedPreferences("com.facebook.login.AuthorizationClient.WebViewAuthHandler.TOKEN_STORE_KEY", 0).edit().putString("TOKEN", str).apply();
                    }
                }
            } catch (FacebookException e) {
                LoginClient.Request request2 = loginClientD.g;
                String message = e.getMessage();
                ArrayList arrayList = new ArrayList();
                if (message != null) {
                    arrayList.add(message);
                }
                result = new LoginClient.Result(request2, qVar, null, TextUtils.join(": ", arrayList), null);
            }
        } else if (facebookException instanceof FacebookOperationCanceledException) {
            result2 = new LoginClient.Result(loginClientD.g, q.CANCEL, null, "User canceled log in.", null);
        } else {
            this.c = null;
            String message2 = facebookException != null ? facebookException.getMessage() : null;
            if (facebookException instanceof FacebookServiceException) {
                FacebookRequestError facebookRequestError = ((FacebookServiceException) facebookException).b;
                strValueOf = String.valueOf(facebookRequestError.b);
                message2 = facebookRequestError.toString();
            }
            String str2 = strValueOf;
            LoginClient.Request request3 = loginClientD.g;
            ArrayList arrayList2 = new ArrayList();
            if (message2 != null) {
                arrayList2.add(message2);
            }
            result = new LoginClient.Result(request3, qVar, null, TextUtils.join(": ", arrayList2), str2);
            result2 = result;
        }
        if (!J.D(this.c)) {
            h(this.c);
        }
        loginClientD.d(result2);
    }
}
