package com.quizlet.api.okhttp.interceptors;

import com.quizlet.data.token.a;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.s;
import okhttp3.u;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AuthorizationInterceptor implements u {

    @NotNull
    private final a accessTokenProvider;

    @NotNull
    private final s baseUrl;

    @NotNull
    private final String clientId;

    public AuthorizationInterceptor(a accessTokenProvider, s baseUrl, String clientId) {
        Intrinsics.checkNotNullParameter(accessTokenProvider, "accessTokenProvider");
        Intrinsics.checkNotNullParameter(baseUrl, "baseUrl");
        Intrinsics.checkNotNullParameter(clientId, "clientId");
        this.accessTokenProvider = accessTokenProvider;
        this.baseUrl = baseUrl;
        this.clientId = clientId;
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0087  */
    @Override // okhttp3.u
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final okhttp3.H intercept(okhttp3.t r6) {
        /*
            r5 = this;
            java.lang.String r0 = "chain"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
            okhttp3.internal.http.f r6 = (okhttp3.internal.http.f) r6
            okhttp3.C r0 = r6.e
            com.quizlet.remote.model.notes.e r1 = r0.b()
            okhttp3.s r0 = r0.a
            java.lang.String r2 = r0.d
            okhttp3.s r3 = r5.baseUrl
            java.lang.String r3 = r3.d
            boolean r2 = kotlin.jvm.internal.Intrinsics.b(r2, r3)
            if (r2 == 0) goto L9d
            com.quizlet.data.token.a r2 = r5.accessTokenProvider
            java.lang.String r2 = r2.a()
            if (r2 == 0) goto L87
            boolean r2 = kotlin.text.StringsKt.O(r2)
            if (r2 == 0) goto L2a
            goto L87
        L2a:
            java.util.ArrayList r2 = r0.f
            int r3 = kotlin.collections.B.i(r2)
            java.lang.Object r3 = r2.get(r3)
            java.lang.String r4 = "direct-login"
            boolean r3 = kotlin.jvm.internal.Intrinsics.b(r3, r4)
            if (r3 != 0) goto L87
            int r3 = kotlin.collections.B.i(r2)
            java.lang.Object r3 = r2.get(r3)
            java.lang.String r4 = "direct-signup"
            boolean r3 = kotlin.jvm.internal.Intrinsics.b(r3, r4)
            if (r3 != 0) goto L87
            int r3 = kotlin.collections.B.i(r2)
            java.lang.Object r3 = r2.get(r3)
            java.lang.String r4 = "google-sign-in-login"
            boolean r3 = kotlin.jvm.internal.Intrinsics.b(r3, r4)
            if (r3 != 0) goto L87
            int r3 = kotlin.collections.B.i(r2)
            java.lang.Object r2 = r2.get(r3)
            java.lang.String r3 = "oauth-extra-info"
            boolean r2 = kotlin.jvm.internal.Intrinsics.b(r2, r3)
            if (r2 == 0) goto L6d
            goto L87
        L6d:
            com.quizlet.data.token.a r0 = r5.accessTokenProvider
            java.lang.String r0 = r0.a()
            java.lang.StringBuilder r2 = new java.lang.StringBuilder
            java.lang.String r3 = "Bearer "
            r2.<init>(r3)
            r2.append(r0)
            java.lang.String r0 = r2.toString()
            java.lang.String r2 = "Authorization"
            r1.l(r2, r0)
            goto L9d
        L87:
            androidx.recyclerview.widget.j r0 = r0.f()
            java.lang.String r2 = "client_id"
            java.lang.String r3 = r5.clientId
            r0.c(r2, r3)
            okhttp3.s r0 = r0.d()
            java.lang.String r2 = "url"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
            r1.b = r0
        L9d:
            okhttp3.C r0 = r1.i()
            okhttp3.H r6 = r6.b(r0)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.api.okhttp.interceptors.AuthorizationInterceptor.intercept(okhttp3.t):okhttp3.H");
    }
}
