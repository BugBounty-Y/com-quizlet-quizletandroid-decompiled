package com.facebook.login;

import android.os.Bundle;
import com.facebook.FacebookException;
import com.facebook.internal.M;
import com.facebook.login.LoginClient;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class G implements M {
    public final /* synthetic */ WebViewLoginMethodHandler a;
    public final /* synthetic */ LoginClient.Request b;

    public G(WebViewLoginMethodHandler webViewLoginMethodHandler, LoginClient.Request request) {
        this.a = webViewLoginMethodHandler;
        this.b = request;
    }

    @Override // com.facebook.internal.M
    public final void a(Bundle bundle, FacebookException facebookException) {
        WebViewLoginMethodHandler webViewLoginMethodHandler = this.a;
        webViewLoginMethodHandler.getClass();
        LoginClient.Request request = this.b;
        Intrinsics.checkNotNullParameter(request, "request");
        webViewLoginMethodHandler.p(request, bundle, facebookException);
    }
}
