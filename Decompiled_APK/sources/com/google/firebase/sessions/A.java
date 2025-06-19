package com.google.firebase.sessions;

/* loaded from: classes2.dex */
public final class A {
    /* JADX WARN: Code restructure failed: missing block: B:37:0x0092, code lost:
    
        if (r10 == r1) goto L38;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r9v14 */
    /* JADX WARN: Type inference failed for: r9v19, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r9v22 */
    /* JADX WARN: Type inference failed for: r9v23 */
    /* JADX WARN: Type inference failed for: r9v4 */
    /* JADX WARN: Type inference failed for: r9v5, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r9v6, types: [java.lang.String] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(com.google.firebase.installations.d r9, kotlin.coroutines.jvm.internal.c r10) {
        /*
            r8 = this;
            boolean r0 = r10 instanceof com.google.firebase.sessions.C4003z
            if (r0 == 0) goto L13
            r0 = r10
            com.google.firebase.sessions.z r0 = (com.google.firebase.sessions.C4003z) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.google.firebase.sessions.z r0 = new com.google.firebase.sessions.z
            r0.<init>(r8, r10)
        L18:
            java.lang.Object r10 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            java.lang.String r3 = ""
            java.lang.String r4 = "InstallationId"
            r5 = 2
            r6 = 1
            if (r2 == 0) goto L48
            if (r2 == r6) goto L3e
            if (r2 != r5) goto L36
            java.lang.Object r9 = r0.j
            java.lang.String r9 = (java.lang.String) r9
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Exception -> L33
            goto L95
        L33:
            r10 = move-exception
            goto L9e
        L36:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L3e:
            java.lang.Object r9 = r0.j
            com.google.firebase.installations.d r9 = (com.google.firebase.installations.d) r9
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Exception -> L46
            goto L65
        L46:
            r10 = move-exception
            goto L78
        L48:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            r10 = r9
            com.google.firebase.installations.c r10 = (com.google.firebase.installations.c) r10     // Catch: java.lang.Exception -> L46
            com.google.android.gms.tasks.m r9 = r10.d()     // Catch: java.lang.Exception -> L46
            java.lang.String r2 = "firebaseInstallations.getToken(false)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r9, r2)     // Catch: java.lang.Exception -> L76
            r0.j = r10     // Catch: java.lang.Exception -> L76
            r0.m = r6     // Catch: java.lang.Exception -> L76
            java.lang.Object r9 = com.google.android.gms.internal.mlkit_vision_camera.M1.c(r9, r0)     // Catch: java.lang.Exception -> L76
            if (r9 != r1) goto L62
            goto L94
        L62:
            r7 = r10
            r10 = r9
            r9 = r7
        L65:
            com.google.firebase.installations.a r10 = (com.google.firebase.installations.a) r10     // Catch: java.lang.Exception -> L46
            java.lang.String r10 = r10.a     // Catch: java.lang.Exception -> L46
            java.lang.String r2 = "{\n          firebaseInst…).await().token\n        }"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r10, r2)     // Catch: java.lang.Exception -> L46
            r7 = r10
            r10 = r9
            r9 = r7
            goto L7f
        L72:
            r7 = r10
            r10 = r9
            r9 = r7
            goto L78
        L76:
            r9 = move-exception
            goto L72
        L78:
            java.lang.String r2 = "Error getting authentication token."
            android.util.Log.w(r4, r2, r10)
            r10 = r9
            r9 = r3
        L7f:
            com.google.firebase.installations.c r10 = (com.google.firebase.installations.c) r10     // Catch: java.lang.Exception -> L33
            com.google.android.gms.tasks.m r10 = r10.c()     // Catch: java.lang.Exception -> L33
            java.lang.String r2 = "firebaseInstallations.id"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r10, r2)     // Catch: java.lang.Exception -> L33
            r0.j = r9     // Catch: java.lang.Exception -> L33
            r0.m = r5     // Catch: java.lang.Exception -> L33
            java.lang.Object r10 = com.google.android.gms.internal.mlkit_vision_camera.M1.c(r10, r0)     // Catch: java.lang.Exception -> L33
            if (r10 != r1) goto L95
        L94:
            return r1
        L95:
            java.lang.String r0 = "{\n          firebaseInst…ions.id.await()\n        }"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r10, r0)     // Catch: java.lang.Exception -> L33
            java.lang.String r10 = (java.lang.String) r10     // Catch: java.lang.Exception -> L33
            r3 = r10
            goto La3
        L9e:
            java.lang.String r0 = "Error getting Firebase installation id ."
            android.util.Log.w(r4, r0, r10)
        La3:
            com.google.firebase.sessions.B r10 = new com.google.firebase.sessions.B
            r10.<init>(r3, r9)
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.sessions.A.a(com.google.firebase.installations.d, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
