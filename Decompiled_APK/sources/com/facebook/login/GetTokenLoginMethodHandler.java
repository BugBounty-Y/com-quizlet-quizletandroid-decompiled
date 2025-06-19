package com.facebook.login;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import com.facebook.AccessToken;
import com.facebook.AuthenticationToken;
import com.facebook.FacebookException;
import com.facebook.login.LoginClient;
import com.google.android.gms.internal.mlkit_vision_common.J2;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class GetTokenLoginMethodHandler extends LoginMethodHandler {

    @NotNull
    public static final Parcelable.Creator<GetTokenLoginMethodHandler> CREATOR = new C1565b(2);
    public m c;
    public final String d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public GetTokenLoginMethodHandler(LoginClient loginClient) {
        super(loginClient);
        Intrinsics.checkNotNullParameter(loginClient, "loginClient");
        this.d = "get_token";
    }

    @Override // com.facebook.login.LoginMethodHandler
    public final void b() {
        m mVar = this.c;
        if (mVar != null) {
            mVar.d = false;
            mVar.c = null;
            this.c = null;
        }
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // com.facebook.login.LoginMethodHandler
    public final String f() {
        return this.d;
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0058 A[DONT_GENERATE] */
    /* JADX WARN: Removed duplicated region for block: B:25:0x005a A[Catch: all -> 0x0099, TRY_ENTER, TryCatch #1 {, blocks: (B:8:0x002a, B:13:0x0033, B:25:0x005a, B:28:0x0064, B:19:0x0051, B:16:0x0041), top: B:49:0x002a, inners: #0 }] */
    @Override // com.facebook.login.LoginMethodHandler
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int m(com.facebook.login.LoginClient.Request r8) {
        /*
            r7 = this;
            java.lang.String r0 = "request"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r0)
            com.facebook.login.m r0 = new com.facebook.login.m
            com.facebook.login.LoginClient r1 = r7.d()
            androidx.fragment.app.I r1 = r1.f()
            if (r1 == 0) goto L12
            goto L16
        L12:
            android.content.Context r1 = com.facebook.o.a()
        L16:
            java.lang.String r2 = "context"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r2)
            java.lang.String r2 = "request"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r2)
            java.lang.String r2 = r8.d
            java.lang.String r3 = r8.o
            r0.<init>(r1, r2, r3)
            r7.c = r0
            monitor-enter(r0)
            boolean r1 = r0.d     // Catch: java.lang.Throwable -> L99
            r2 = 0
            r3 = 1
            if (r1 == 0) goto L33
            monitor-exit(r0)
        L31:
            r1 = r2
            goto L6d
        L33:
            int r1 = r0.i     // Catch: java.lang.Throwable -> L99
            com.facebook.internal.C r4 = com.facebook.internal.C.a     // Catch: java.lang.Throwable -> L99
            java.lang.Class<com.facebook.internal.C> r4 = com.facebook.internal.C.class
            boolean r5 = com.facebook.internal.instrument.crashshield.a.b(r4)     // Catch: java.lang.Throwable -> L99
            if (r5 == 0) goto L41
        L3f:
            r1 = r2
            goto L55
        L41:
            com.facebook.internal.C r5 = com.facebook.internal.C.a     // Catch: java.lang.Throwable -> L50
            java.util.ArrayList r6 = com.facebook.internal.C.b     // Catch: java.lang.Throwable -> L50
            int[] r1 = new int[]{r1}     // Catch: java.lang.Throwable -> L50
            com.airbnb.lottie.parser.l r1 = r5.g(r6, r1)     // Catch: java.lang.Throwable -> L50
            int r1 = r1.b     // Catch: java.lang.Throwable -> L50
            goto L55
        L50:
            r1 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r4, r1)     // Catch: java.lang.Throwable -> L99
            goto L3f
        L55:
            r4 = -1
            if (r1 != r4) goto L5a
            monitor-exit(r0)
            goto L31
        L5a:
            android.content.Context r1 = r0.a     // Catch: java.lang.Throwable -> L99
            android.content.Intent r1 = com.facebook.internal.C.d(r1)     // Catch: java.lang.Throwable -> L99
            if (r1 != 0) goto L64
            r1 = r2
            goto L6c
        L64:
            r0.d = r3     // Catch: java.lang.Throwable -> L99
            android.content.Context r4 = r0.a     // Catch: java.lang.Throwable -> L99
            r4.bindService(r1, r0, r3)     // Catch: java.lang.Throwable -> L99
            r1 = r3
        L6c:
            monitor-exit(r0)
        L6d:
            if (r1 != 0) goto L70
            return r2
        L70:
            com.facebook.login.LoginClient r0 = r7.d()
            androidx.webkit.internal.p r0 = r0.e
            if (r0 == 0) goto L8b
            java.lang.Object r0 = r0.b
            com.facebook.login.u r0 = (com.facebook.login.u) r0
            android.view.View r0 = r0.e
            if (r0 == 0) goto L84
            r0.setVisibility(r2)
            goto L8b
        L84:
            java.lang.String r8 = "progressBar"
            kotlin.jvm.internal.Intrinsics.m(r8)
            r8 = 0
            throw r8
        L8b:
            androidx.camera.camera2.internal.u r0 = new androidx.camera.camera2.internal.u
            r1 = 18
            r0.<init>(r1, r7, r8)
            com.facebook.login.m r8 = r7.c
            if (r8 == 0) goto L98
            r8.c = r0
        L98:
            return r3
        L99:
            r8 = move-exception
            monitor-exit(r0)
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.login.GetTokenLoginMethodHandler.m(com.facebook.login.LoginClient$Request):int");
    }

    public final void n(LoginClient.Request request, Bundle bundle) {
        LoginClient.Result result;
        AuthenticationToken authenticationToken;
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(bundle, "result");
        try {
            AccessToken accessTokenB = J2.b(bundle, request.d);
            String str = request.o;
            Intrinsics.checkNotNullParameter(bundle, "bundle");
            String string = bundle.getString("com.facebook.platform.extra.ID_TOKEN");
            if (string == null || string.length() == 0 || str == null || str.length() == 0) {
                authenticationToken = null;
            } else {
                try {
                    authenticationToken = new AuthenticationToken(string, str);
                } catch (Exception e) {
                    throw new FacebookException(e.getMessage());
                }
            }
            result = new LoginClient.Result(request, q.SUCCESS, accessTokenB, authenticationToken, null, null);
        } catch (FacebookException e2) {
            LoginClient.Request request2 = d().g;
            String message = e2.getMessage();
            ArrayList arrayList = new ArrayList();
            if (message != null) {
                arrayList.add(message);
            }
            result = new LoginClient.Result(request2, q.ERROR, null, TextUtils.join(": ", arrayList), null);
        }
        d().d(result);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public GetTokenLoginMethodHandler(Parcel source) {
        super(source);
        Intrinsics.checkNotNullParameter(source, "source");
        this.d = "get_token";
    }
}
