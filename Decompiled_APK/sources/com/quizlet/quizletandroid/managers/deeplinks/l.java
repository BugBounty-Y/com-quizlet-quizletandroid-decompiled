package com.quizlet.quizletandroid.managers.deeplinks;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes3.dex */
public final class l {
    public static final kotlin.u d = kotlin.l.b(new com.quizlet.login.resetpassword.ui.a(5));
    public final AbstractC5040y a;
    public final com.quizlet.quizletandroid.config.c b;
    public final h c;

    public l(AbstractC5040y ioDispatcher, com.quizlet.quizletandroid.config.c marketingDeepLinkAllowlist, h urlCreator) {
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        Intrinsics.checkNotNullParameter(marketingDeepLinkAllowlist, "marketingDeepLinkAllowlist");
        Intrinsics.checkNotNullParameter(urlCreator, "urlCreator");
        this.a = ioDispatcher;
        this.b = marketingDeepLinkAllowlist;
        this.c = urlCreator;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Comparable a(android.net.Uri r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.quizletandroid.managers.deeplinks.j
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.quizletandroid.managers.deeplinks.j r0 = (com.quizlet.quizletandroid.managers.deeplinks.j) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.managers.deeplinks.j r0 = new com.quizlet.quizletandroid.managers.deeplinks.j
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.quizletandroid.managers.deeplinks.l r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L40
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r4
            r0.m = r3
            java.lang.Comparable r6 = r4.b(r5, r0)
            if (r6 != r1) goto L3f
            return r1
        L3f:
            r5 = r4
        L40:
            android.net.Uri r6 = (android.net.Uri) r6
            r5.getClass()
            java.lang.String r5 = r6.getPath()
            java.lang.String r0 = "/p/wordlywise3000"
            boolean r5 = kotlin.jvm.internal.Intrinsics.b(r5, r0)
            if (r5 == 0) goto L5d
            kotlin.u r5 = com.quizlet.quizletandroid.managers.deeplinks.l.d
            java.lang.Object r5 = r5.getValue()
            android.net.Uri r5 = (android.net.Uri) r5
            kotlin.jvm.internal.Intrinsics.d(r5)
            return r5
        L5d:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.managers.deeplinks.l.a(android.net.Uri, kotlin.coroutines.jvm.internal.c):java.lang.Comparable");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0015  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Comparable b(android.net.Uri r8, kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            r7 = this;
            java.lang.String r0 = "Resolved marketing url: "
            boolean r1 = r9 instanceof com.quizlet.quizletandroid.managers.deeplinks.k
            if (r1 == 0) goto L15
            r1 = r9
            com.quizlet.quizletandroid.managers.deeplinks.k r1 = (com.quizlet.quizletandroid.managers.deeplinks.k) r1
            int r2 = r1.n
            r3 = -2147483648(0xffffffff80000000, float:-0.0)
            r4 = r2 & r3
            if (r4 == 0) goto L15
            int r2 = r2 - r3
            r1.n = r2
            goto L1a
        L15:
            com.quizlet.quizletandroid.managers.deeplinks.k r1 = new com.quizlet.quizletandroid.managers.deeplinks.k
            r1.<init>(r7, r9)
        L1a:
            java.lang.Object r9 = r1.l
            kotlin.coroutines.intrinsics.a r2 = kotlin.coroutines.intrinsics.a.a
            int r3 = r1.n
            r4 = 1
            r5 = 0
            if (r3 == 0) goto L40
            if (r3 != r4) goto L38
            java.lang.String r8 = r1.k
            android.net.Uri r1 = r1.j
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.io.IOException -> L32 java.lang.NullPointerException -> L35
            r6 = r9
            r9 = r8
            r8 = r1
            r1 = r6
            goto L7e
        L32:
            r9 = move-exception
            goto La1
        L35:
            r8 = move-exception
            goto Laf
        L38:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L40:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.quizlet.quizletandroid.config.c r9 = r7.b
            boolean r9 = r9.a(r8)
            if (r9 == 0) goto Lb9
            java.util.List r9 = r8.getPathSegments()
            java.lang.String r3 = "getPathSegments(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r9, r3)
            java.lang.Object r9 = kotlin.collections.CollectionsKt.firstOrNull(r9)
            java.lang.String r3 = "uni"
            boolean r9 = kotlin.jvm.internal.Intrinsics.b(r9, r3)
            if (r9 == 0) goto Lb9
            java.lang.String r9 = r8.toString()
            java.lang.String r3 = "toString(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r9, r3)
            r1.j = r8     // Catch: java.io.IOException -> L98 java.lang.NullPointerException -> L9d
            r1.k = r9     // Catch: java.io.IOException -> L98 java.lang.NullPointerException -> L9d
            r1.n = r4     // Catch: java.io.IOException -> L98 java.lang.NullPointerException -> L9d
            com.quizlet.quizletandroid.managers.deeplinks.i r3 = new com.quizlet.quizletandroid.managers.deeplinks.i     // Catch: java.io.IOException -> L98 java.lang.NullPointerException -> L9d
            r4 = 0
            r3.<init>(r7, r9, r4)     // Catch: java.io.IOException -> L98 java.lang.NullPointerException -> L9d
            kotlinx.coroutines.y r4 = r7.a     // Catch: java.io.IOException -> L98 java.lang.NullPointerException -> L9d
            java.lang.Object r1 = kotlinx.coroutines.E.J(r4, r3, r1)     // Catch: java.io.IOException -> L98 java.lang.NullPointerException -> L9d
            if (r1 != r2) goto L7e
            return r2
        L7e:
            java.lang.String r1 = (java.lang.String) r1     // Catch: java.io.IOException -> L98 java.lang.NullPointerException -> L9d
            timber.log.a r2 = timber.log.c.a     // Catch: java.io.IOException -> L98 java.lang.NullPointerException -> L9d
            java.lang.StringBuilder r3 = new java.lang.StringBuilder     // Catch: java.io.IOException -> L98 java.lang.NullPointerException -> L9d
            r3.<init>(r0)     // Catch: java.io.IOException -> L98 java.lang.NullPointerException -> L9d
            r3.append(r1)     // Catch: java.io.IOException -> L98 java.lang.NullPointerException -> L9d
            java.lang.String r0 = r3.toString()     // Catch: java.io.IOException -> L98 java.lang.NullPointerException -> L9d
            java.lang.Object[] r3 = new java.lang.Object[r5]     // Catch: java.io.IOException -> L98 java.lang.NullPointerException -> L9d
            r2.g(r0, r3)     // Catch: java.io.IOException -> L98 java.lang.NullPointerException -> L9d
            android.net.Uri r8 = android.net.Uri.parse(r1)     // Catch: java.io.IOException -> L98 java.lang.NullPointerException -> L9d
            return r8
        L98:
            r0 = move-exception
            r1 = r8
            r8 = r9
            r9 = r0
            goto La1
        L9d:
            r9 = move-exception
            r1 = r8
            r8 = r9
            goto Laf
        La1:
            timber.log.a r0 = timber.log.c.a
            java.lang.String r2 = "Problem opening connection to the Url: "
            java.lang.String r8 = androidx.camera.camera2.internal.AbstractC0147y.d(r2, r8)
            java.lang.Object[] r2 = new java.lang.Object[r5]
            r0.i(r9, r8, r2)
            goto Lb8
        Laf:
            timber.log.a r9 = timber.log.c.a
            java.lang.String r0 = "Not a valid resolved url"
            java.lang.Object[] r2 = new java.lang.Object[r5]
            r9.i(r8, r0, r2)
        Lb8:
            return r1
        Lb9:
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.managers.deeplinks.l.b(android.net.Uri, kotlin.coroutines.jvm.internal.c):java.lang.Comparable");
    }
}
