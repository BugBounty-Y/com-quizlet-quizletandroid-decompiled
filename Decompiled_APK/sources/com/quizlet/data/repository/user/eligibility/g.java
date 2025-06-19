package com.quizlet.data.repository.user.eligibility;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class g {
    public final com.quizlet.data.interactor.achievements.f a;
    public final com.quizlet.data.repository.searchexplanations.c b;
    public final org.slf4j.b c;
    public final kotlinx.coroutines.internal.d d;

    public g(com.quizlet.data.interactor.achievements.f localRepository, com.quizlet.data.repository.searchexplanations.c remoteRepository, org.slf4j.b logger, kotlinx.coroutines.internal.d defaultScope) {
        Intrinsics.checkNotNullParameter(localRepository, "localRepository");
        Intrinsics.checkNotNullParameter(remoteRepository, "remoteRepository");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(defaultScope, "defaultScope");
        this.a = localRepository;
        this.b = remoteRepository;
        this.c = logger;
        this.d = defaultScope;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.data.repository.user.eligibility.a
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.data.repository.user.eligibility.a r0 = (com.quizlet.data.repository.user.eligibility.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.repository.user.eligibility.a r0 = new com.quizlet.data.repository.user.eligibility.a
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            com.quizlet.data.repository.user.eligibility.g r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)     // Catch: java.lang.Throwable -> L29
            goto L57
        L29:
            r5 = move-exception
            goto L50
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            com.quizlet.data.interactor.achievements.f r5 = r4.a     // Catch: java.lang.Throwable -> L4e
            r0.j = r4     // Catch: java.lang.Throwable -> L4e
            r0.m = r3     // Catch: java.lang.Throwable -> L4e
            java.lang.Object r5 = r5.b     // Catch: java.lang.Throwable -> L4e
            com.quizlet.local.cache.caches.b r5 = (com.quizlet.local.cache.caches.b) r5     // Catch: java.lang.Throwable -> L4e
            java.lang.Object r5 = r5.b     // Catch: java.lang.Throwable -> L4e
            java.util.LinkedHashMap r5 = (java.util.LinkedHashMap) r5     // Catch: java.lang.Throwable -> L4e
            r5.clear()     // Catch: java.lang.Throwable -> L4e
            kotlin.Unit r5 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L4e
            if (r5 != r1) goto L57
            return r1
        L4c:
            r0 = r4
            goto L50
        L4e:
            r5 = move-exception
            goto L4c
        L50:
            org.slf4j.b r0 = r0.c
            java.lang.String r1 = "Failed to clear feature eligibility from local storage"
            r0.c(r1, r5)
        L57:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.user.eligibility.g.a(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable b(java.util.Set r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r6 = this;
            boolean r0 = r8 instanceof com.quizlet.data.repository.user.eligibility.b
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.data.repository.user.eligibility.b r0 = (com.quizlet.data.repository.user.eligibility.b) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.data.repository.user.eligibility.b r0 = new com.quizlet.data.repository.user.eligibility.b
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L42
            if (r2 == r4) goto L36
            if (r2 != r3) goto L2e
            java.lang.Object r7 = r0.j
            java.util.Map r7 = (java.util.Map) r7
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L7d
        L2e:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L36:
            java.util.Set r7 = r0.k
            java.util.Set r7 = (java.util.Set) r7
            java.lang.Object r2 = r0.j
            com.quizlet.data.repository.user.eligibility.g r2 = (com.quizlet.data.repository.user.eligibility.g) r2
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L56
        L42:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.j = r6
            r8 = r7
            java.util.Set r8 = (java.util.Set) r8
            r0.k = r8
            r0.n = r4
            java.lang.Object r8 = r6.c(r7, r0)
            if (r8 != r1) goto L55
            goto L79
        L55:
            r2 = r6
        L56:
            java.util.Map r8 = (java.util.Map) r8
            java.util.Set r4 = r8.keySet()
            java.lang.Iterable r4 = (java.lang.Iterable) r4
            java.util.Set r7 = kotlin.collections.b0.e(r7, r4)
            r4 = r7
            java.util.Collection r4 = (java.util.Collection) r4
            boolean r4 = r4.isEmpty()
            if (r4 != 0) goto L80
            r0.j = r8
            r4 = 0
            r0.k = r4
            r0.n = r3
            r3 = 0
            java.lang.Object r7 = r2.e(r7, r3, r0)
            if (r7 != r1) goto L7a
        L79:
            return r1
        L7a:
            r5 = r8
            r8 = r7
            r7 = r5
        L7d:
            java.util.Map r8 = (java.util.Map) r8
            goto L87
        L80:
            kotlin.collections.L r7 = kotlin.collections.V.c()
            r5 = r8
            r8 = r7
            r7 = r5
        L87:
            java.util.LinkedHashMap r7 = kotlin.collections.V.h(r7, r8)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.user.eligibility.g.b(java.util.Set, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(java.util.Set r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.data.repository.user.eligibility.c
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.data.repository.user.eligibility.c r0 = (com.quizlet.data.repository.user.eligibility.c) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.repository.user.eligibility.c r0 = new com.quizlet.data.repository.user.eligibility.c
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            com.quizlet.data.repository.user.eligibility.g r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: java.lang.Throwable -> L29
            goto L44
        L29:
            r6 = move-exception
            goto L4b
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.quizlet.data.interactor.achievements.f r6 = r4.a     // Catch: java.lang.Throwable -> L49
            r0.j = r4     // Catch: java.lang.Throwable -> L49
            r0.m = r3     // Catch: java.lang.Throwable -> L49
            java.lang.Object r6 = r6.b(r5, r0)     // Catch: java.lang.Throwable -> L49
            if (r6 != r1) goto L43
            return r1
        L43:
            r5 = r4
        L44:
            java.util.Map r6 = (java.util.Map) r6     // Catch: java.lang.Throwable -> L29
            return r6
        L47:
            r5 = r4
            goto L4b
        L49:
            r6 = move-exception
            goto L47
        L4b:
            org.slf4j.b r5 = r5.c
            java.lang.String r0 = "Failed to get feature eligibility from local storage"
            r5.c(r0, r6)
            kotlin.collections.L r5 = kotlin.collections.V.c()
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.user.eligibility.g.c(java.util.Set, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(java.util.Set r6, kotlin.coroutines.jvm.internal.c r7) throws java.lang.Throwable {
        /*
            r5 = this;
            boolean r0 = r7 instanceof com.quizlet.data.repository.user.eligibility.d
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.repository.user.eligibility.d r0 = (com.quizlet.data.repository.user.eligibility.d) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.repository.user.eligibility.d r0 = new com.quizlet.data.repository.user.eligibility.d
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3c
            if (r2 == r4) goto L34
            if (r2 != r3) goto L2c
            java.lang.Object r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            return r6
        L2c:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L34:
            java.lang.Object r6 = r0.j
            com.quizlet.data.repository.user.eligibility.g r6 = (com.quizlet.data.repository.user.eligibility.g) r6
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L5a
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r5
            r0.m = r4
            com.quizlet.data.repository.searchexplanations.c r7 = r5.b
            r7.getClass()
            com.quizlet.remote.model.user.eligibility.a r2 = new com.quizlet.remote.model.user.eligibility.a
            r4 = 0
            r2.<init>(r6, r7, r4)
            java.lang.Object r6 = r7.c
            kotlinx.coroutines.y r6 = (kotlinx.coroutines.AbstractC5040y) r6
            java.lang.Object r7 = kotlinx.coroutines.E.J(r6, r2, r0)
            if (r7 != r1) goto L59
            goto L74
        L59:
            r6 = r5
        L5a:
            r2 = r7
            java.util.Map r2 = (java.util.Map) r2
            r0.j = r7
            r0.m = r3
            r6.getClass()
            com.quizlet.data.repository.user.eligibility.f r0 = new com.quizlet.data.repository.user.eligibility.f
            r3 = 0
            r0.<init>(r6, r2, r3)
            kotlinx.coroutines.internal.d r6 = r6.d
            r2 = 3
            kotlinx.coroutines.E.A(r6, r3, r3, r0, r2)
            kotlin.Unit r6 = kotlin.Unit.a
            if (r6 != r1) goto L75
        L74:
            return r1
        L75:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.user.eligibility.g.d(java.util.Set, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:28:0x0065, code lost:
    
        if (r8 == r1) goto L29;
     */
    /* JADX WARN: Removed duplicated region for block: B:27:0x005a  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x006b  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object e(java.util.Set r6, boolean r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r5 = this;
            boolean r0 = r8 instanceof com.quizlet.data.repository.user.eligibility.e
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.data.repository.user.eligibility.e r0 = (com.quizlet.data.repository.user.eligibility.e) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.data.repository.user.eligibility.e r0 = new com.quizlet.data.repository.user.eligibility.e
            r0.<init>(r5, r8)
        L18:
            java.lang.Object r8 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3e
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L68
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L32:
            boolean r7 = r0.l
            java.util.Set r6 = r0.k
            java.util.Set r6 = (java.util.Set) r6
            com.quizlet.data.repository.user.eligibility.g r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)     // Catch: java.lang.Throwable -> L58
            goto L54
        L3e:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.j = r5     // Catch: java.lang.Throwable -> L57
            r8 = r6
            java.util.Set r8 = (java.util.Set) r8     // Catch: java.lang.Throwable -> L57
            r0.k = r8     // Catch: java.lang.Throwable -> L57
            r0.l = r7     // Catch: java.lang.Throwable -> L57
            r0.o = r4     // Catch: java.lang.Throwable -> L57
            java.lang.Object r8 = r5.d(r6, r0)     // Catch: java.lang.Throwable -> L57
            if (r8 != r1) goto L53
            goto L67
        L53:
            r2 = r5
        L54:
            java.util.Map r8 = (java.util.Map) r8     // Catch: java.lang.Throwable -> L58
            return r8
        L57:
            r2 = r5
        L58:
            if (r7 == 0) goto L6b
            r7 = 0
            r0.j = r7
            r0.k = r7
            r0.o = r3
            java.lang.Object r8 = r2.c(r6, r0)
            if (r8 != r1) goto L68
        L67:
            return r1
        L68:
            java.util.Map r8 = (java.util.Map) r8
            goto L6f
        L6b:
            kotlin.collections.L r8 = kotlin.collections.V.c()
        L6f:
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.user.eligibility.g.e(java.util.Set, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
