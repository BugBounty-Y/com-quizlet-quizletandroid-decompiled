package com.quizlet.features.infra.google;

import android.content.Context;
import androidx.credentials.o;
import com.google.android.gms.common.GoogleApiAvailability;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public final Context a;
    public final o b;
    public final o c;
    public final o d;
    public final com.quizlet.shared.usecase.srs.a e;
    public final GoogleApiAvailability f;

    public e(Context context, androidx.credentials.f credentialManager, o requestSignIn, o requestSignBackIn, o requestReAuth, com.quizlet.shared.usecase.srs.a googleIdTokenCredentialCreator, GoogleApiAvailability googleApiAvailability) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(credentialManager, "credentialManager");
        Intrinsics.checkNotNullParameter(requestSignIn, "requestSignIn");
        Intrinsics.checkNotNullParameter(requestSignBackIn, "requestSignBackIn");
        Intrinsics.checkNotNullParameter(requestReAuth, "requestReAuth");
        Intrinsics.checkNotNullParameter(googleIdTokenCredentialCreator, "googleIdTokenCredentialCreator");
        Intrinsics.checkNotNullParameter(googleApiAvailability, "googleApiAvailability");
        this.a = context;
        this.b = requestSignIn;
        this.c = requestSignBackIn;
        this.d = requestReAuth;
        this.e = googleIdTokenCredentialCreator;
        this.f = googleApiAvailability;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.features.infra.google.a
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.features.infra.google.a r0 = (com.quizlet.features.infra.google.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.infra.google.a r0 = new com.quizlet.features.infra.google.a
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r5)
            kotlin.r r5 = (kotlin.r) r5
            java.lang.Object r5 = r5.a
            return r5
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.l = r3
            androidx.credentials.o r5 = r4.d
            r2 = 0
            java.io.Serializable r5 = r4.d(r5, r2, r0)
            if (r5 != r1) goto L42
            return r1
        L42:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.google.e.a(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.features.infra.google.b
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.features.infra.google.b r0 = (com.quizlet.features.infra.google.b) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.infra.google.b r0 = new com.quizlet.features.infra.google.b
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r5)
            kotlin.r r5 = (kotlin.r) r5
            java.lang.Object r5 = r5.a
            return r5
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.l = r3
            androidx.credentials.o r5 = r4.c
            java.io.Serializable r5 = r4.d(r5, r3, r0)
            if (r5 != r1) goto L41
            return r1
        L41:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.google.e.b(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.features.infra.google.c
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.features.infra.google.c r0 = (com.quizlet.features.infra.google.c) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.infra.google.c r0 = new com.quizlet.features.infra.google.c
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r5)
            kotlin.r r5 = (kotlin.r) r5
            java.lang.Object r5 = r5.a
            return r5
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.l = r3
            androidx.credentials.o r5 = r4.b
            r2 = 0
            java.io.Serializable r5 = r4.d(r5, r2, r0)
            if (r5 != r1) goto L42
            return r1
        L42:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.google.e.c(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x009a  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x009d A[Catch: all -> 0x002e, TRY_ENTER, TryCatch #2 {all -> 0x002e, blocks: (B:12:0x002a, B:31:0x0074, B:33:0x007f, B:35:0x008b, B:39:0x009d, B:40:0x00a0, B:41:0x00a7), top: B:58:0x002a }] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00a0 A[Catch: all -> 0x002e, TryCatch #2 {all -> 0x002e, blocks: (B:12:0x002a, B:31:0x0074, B:33:0x007f, B:35:0x008b, B:39:0x009d, B:40:0x00a0, B:41:0x00a7), top: B:58:0x002a }] */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00b9  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable d(androidx.credentials.o r7, boolean r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r6 = this;
            boolean r0 = r9 instanceof com.quizlet.features.infra.google.d
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.features.infra.google.d r0 = (com.quizlet.features.infra.google.d) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.features.infra.google.d r0 = new com.quizlet.features.infra.google.d
            r0.<init>(r6, r9)
        L18:
            java.lang.Object r9 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            r4 = 0
            if (r2 == 0) goto L39
            if (r2 != r3) goto L31
            boolean r8 = r0.l
            com.quizlet.features.infra.google.e r7 = r0.k
            com.quizlet.features.infra.google.e r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Throwable -> L2e
            goto L74
        L2e:
            r7 = move-exception
            goto Lac
        L31:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L39:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            int r9 = com.google.android.gms.common.c.a
            com.google.android.gms.common.GoogleApiAvailability r2 = r6.f
            android.content.Context r5 = r6.a
            int r9 = r2.c(r5, r9)
            if (r9 == 0) goto L61
            if (r8 != 0) goto L5e
            java.lang.String r7 = "null cannot be cast to non-null type android.app.Activity"
            kotlin.jvm.internal.Intrinsics.e(r5, r7)
            android.app.Activity r5 = (android.app.Activity) r5
            r7 = -1
            android.app.AlertDialog r7 = r2.d(r5, r9, r7, r4)
            if (r7 != 0) goto L59
            goto L5e
        L59:
            java.lang.String r8 = "GooglePlayServicesErrorDialog"
            com.google.android.gms.common.GoogleApiAvailability.h(r5, r7, r8, r4)
        L5e:
            kotlin.p r7 = kotlin.r.b
            return r4
        L61:
            kotlin.p r9 = kotlin.r.b     // Catch: java.lang.Throwable -> Laa
            r0.j = r6     // Catch: java.lang.Throwable -> Laa
            r0.k = r6     // Catch: java.lang.Throwable -> Laa
            r0.l = r8     // Catch: java.lang.Throwable -> Laa
            r0.o = r3     // Catch: java.lang.Throwable -> Laa
            java.lang.Object r9 = androidx.credentials.f.b(r5, r7, r0)     // Catch: java.lang.Throwable -> Laa
            if (r9 != r1) goto L72
            return r1
        L72:
            r7 = r6
            r0 = r7
        L74:
            androidx.credentials.p r9 = (androidx.credentials.p) r9     // Catch: java.lang.Throwable -> L2e
            r7.getClass()     // Catch: java.lang.Throwable -> L2e
            androidx.appcompat.app.y r9 = r9.a     // Catch: java.lang.Throwable -> L2e
            boolean r1 = r9 instanceof androidx.credentials.m     // Catch: java.lang.Throwable -> L2e
            if (r1 == 0) goto L9a
            java.lang.Object r1 = r9.b     // Catch: java.lang.Throwable -> L2e
            java.lang.String r1 = (java.lang.String) r1     // Catch: java.lang.Throwable -> L2e
            java.lang.String r2 = "com.google.android.libraries.identity.googleid.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL"
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r1, r2)     // Catch: java.lang.Throwable -> L2e
            if (r1 == 0) goto L9a
            com.quizlet.shared.usecase.srs.a r7 = r7.e     // Catch: java.lang.Throwable -> L2e com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException -> L9a
            java.lang.Object r9 = r9.c     // Catch: java.lang.Throwable -> L2e com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException -> L9a
            android.os.Bundle r9 = (android.os.Bundle) r9     // Catch: java.lang.Throwable -> L2e com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException -> L9a
            java.lang.Object r7 = r7.t(r9)     // Catch: java.lang.Throwable -> L2e com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException -> L9a
            com.google.android.libraries.identity.googleid.c r7 = (com.google.android.libraries.identity.googleid.c) r7     // Catch: java.lang.Throwable -> L2e com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException -> L9a
            java.lang.String r7 = r7.d     // Catch: java.lang.Throwable -> L2e com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException -> L9a
            goto L9b
        L9a:
            r7 = r4
        L9b:
            if (r7 == 0) goto La0
            kotlin.p r9 = kotlin.r.b     // Catch: java.lang.Throwable -> L2e
            goto Lb2
        La0:
            java.lang.Exception r7 = new java.lang.Exception     // Catch: java.lang.Throwable -> L2e
            java.lang.String r9 = "Unable to get Google id token"
            r7.<init>(r9)     // Catch: java.lang.Throwable -> L2e
            throw r7     // Catch: java.lang.Throwable -> L2e
        La8:
            r0 = r6
            goto Lac
        Laa:
            r7 = move-exception
            goto La8
        Lac:
            kotlin.p r9 = kotlin.r.b
            kotlin.q r7 = androidx.glance.appwidget.protobuf.Z.b(r7)
        Lb2:
            r0.getClass()
            boolean r9 = r7 instanceof kotlin.q
            if (r9 == 0) goto Lc3
            java.lang.Throwable r9 = kotlin.r.a(r7)
            boolean r9 = r9 instanceof androidx.credentials.exceptions.GetCredentialCancellationException
            if (r9 != 0) goto Lc4
            if (r8 != 0) goto Lc4
        Lc3:
            r4 = r7
        Lc4:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.google.e.d(androidx.credentials.o, boolean, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }
}
