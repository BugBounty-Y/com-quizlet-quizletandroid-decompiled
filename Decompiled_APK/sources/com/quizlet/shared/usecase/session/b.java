package com.quizlet.shared.usecase.session;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final com.quizlet.shared.cache.a a;
    public final com.quizlet.shared.cache.a b;

    public b(com.quizlet.shared.cache.a persistentCache, com.quizlet.shared.cache.a inMemoryCache) {
        Intrinsics.checkNotNullParameter(persistentCache, "persistentCache");
        Intrinsics.checkNotNullParameter(inMemoryCache, "inMemoryCache");
        this.a = persistentCache;
        this.b = inMemoryCache;
    }

    /* JADX WARN: Can't wrap try/catch for region: R(13:0|2|(2:4|(1:6)(1:7))(0)|8|(1:(1:(8:12|62|13|42|48|(1:50)|51|(2:53|64)(2:54|55))(2:17|18))(3:19|56|20))(5:24|58|25|(1:28)|40)|29|35|(1:37)|60|38|(6:41|42|48|(0)|51|(0)(0))|40|(1:(0))) */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x008b, code lost:
    
        r0 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x008d, code lost:
    
        r7 = th;
     */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0073  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0085  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x009b  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00a3  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00a8  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.jvm.internal.c r7) {
        /*
            r6 = this;
            boolean r0 = r7 instanceof com.quizlet.shared.usecase.session.a
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.shared.usecase.session.a r0 = (com.quizlet.shared.usecase.session.a) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.shared.usecase.session.a r0 = new com.quizlet.shared.usecase.session.a
            r0.<init>(r6, r7)
        L18:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L44
            if (r2 == r4) goto L38
            if (r2 != r3) goto L30
            java.lang.Object r0 = r0.j
            kotlin.jvm.internal.J r0 = (kotlin.jvm.internal.J) r0
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: java.lang.Throwable -> L2e
            goto L86
        L2e:
            r7 = move-exception
            goto L8f
        L30:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L38:
            kotlin.jvm.internal.J r2 = r0.k
            java.lang.Object r4 = r0.j
            com.quizlet.shared.usecase.session.b r4 = (com.quizlet.shared.usecase.session.b) r4
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: java.lang.Throwable -> L42
            goto L5e
        L42:
            r7 = move-exception
            goto L67
        L44:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.jvm.internal.J r2 = new kotlin.jvm.internal.J
            r2.<init>()
            kotlin.p r7 = kotlin.r.b     // Catch: java.lang.Throwable -> L65
            com.quizlet.shared.cache.a r7 = r6.b     // Catch: java.lang.Throwable -> L65
            r0.j = r6     // Catch: java.lang.Throwable -> L65
            r0.k = r2     // Catch: java.lang.Throwable -> L65
            r0.n = r4     // Catch: java.lang.Throwable -> L65
            java.lang.Object r7 = r7.c(r0)     // Catch: java.lang.Throwable -> L65
            if (r7 != r1) goto L5d
            goto L84
        L5d:
            r4 = r6
        L5e:
            kotlin.Unit r7 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L42
            kotlin.p r5 = kotlin.r.b     // Catch: java.lang.Throwable -> L42
            goto L6d
        L63:
            r4 = r6
            goto L67
        L65:
            r7 = move-exception
            goto L63
        L67:
            kotlin.p r5 = kotlin.r.b
            kotlin.q r7 = androidx.glance.appwidget.protobuf.Z.b(r7)
        L6d:
            java.lang.Throwable r7 = kotlin.r.a(r7)
            if (r7 == 0) goto L75
            r2.a = r7
        L75:
            com.quizlet.shared.cache.a r7 = r4.a     // Catch: java.lang.Throwable -> L8d
            r0.j = r2     // Catch: java.lang.Throwable -> L8d
            r4 = 0
            r0.k = r4     // Catch: java.lang.Throwable -> L8d
            r0.n = r3     // Catch: java.lang.Throwable -> L8d
            java.lang.Object r7 = r7.c(r0)     // Catch: java.lang.Throwable -> L8d
            if (r7 != r1) goto L85
        L84:
            return r1
        L85:
            r0 = r2
        L86:
            kotlin.Unit r7 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L2e
            kotlin.p r1 = kotlin.r.b     // Catch: java.lang.Throwable -> L2e
            goto L95
        L8b:
            r0 = r2
            goto L8f
        L8d:
            r7 = move-exception
            goto L8b
        L8f:
            kotlin.p r1 = kotlin.r.b
            kotlin.q r7 = androidx.glance.appwidget.protobuf.Z.b(r7)
        L95:
            java.lang.Throwable r7 = kotlin.r.a(r7)
            if (r7 == 0) goto L9d
            r0.a = r7
        L9d:
            java.lang.Object r7 = r0.a
            java.lang.Throwable r7 = (java.lang.Throwable) r7
            if (r7 == 0) goto La8
            kotlin.q r7 = androidx.glance.appwidget.protobuf.Z.b(r7)
            goto Laa
        La8:
            kotlin.Unit r7 = kotlin.Unit.a
        Laa:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.usecase.session.b.a(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
