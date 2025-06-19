package com.quizlet.data.repository.folder;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class i {
    public final androidx.work.impl.model.c a;
    public final com.quizlet.data.connectivity.a b;
    public final com.quizlet.data.interactor.set.c c;
    public final org.slf4j.b d;

    public i(androidx.work.impl.model.c factory, com.quizlet.data.connectivity.a networkStatus, com.quizlet.data.interactor.set.c repository, org.slf4j.b logger) {
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.a = factory;
        this.b = networkStatus;
        this.c = repository;
        this.d = logger;
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x0079, code lost:
    
        if (r1 == r3) goto L24;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0017  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(long r17, long r19, long r21, boolean r23, kotlin.coroutines.jvm.internal.c r24) throws java.lang.Throwable {
        /*
            r16 = this;
            r0 = r16
            r1 = r24
            boolean r2 = r1 instanceof com.quizlet.data.repository.folder.a
            if (r2 == 0) goto L17
            r2 = r1
            com.quizlet.data.repository.folder.a r2 = (com.quizlet.data.repository.folder.a) r2
            int r3 = r2.m
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L17
            int r3 = r3 - r4
            r2.m = r3
            goto L1c
        L17:
            com.quizlet.data.repository.folder.a r2 = new com.quizlet.data.repository.folder.a
            r2.<init>(r0, r1)
        L1c:
            java.lang.Object r1 = r2.k
            kotlin.coroutines.intrinsics.a r3 = kotlin.coroutines.intrinsics.a.a
            int r4 = r2.m
            r5 = 2
            r6 = 1
            if (r4 == 0) goto L3c
            if (r4 == r6) goto L36
            if (r4 != r5) goto L2e
            androidx.glance.appwidget.protobuf.Z.e(r1)
            goto L7c
        L2e:
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r1.<init>(r2)
            throw r1
        L36:
            com.quizlet.data.repository.folder.i r4 = r2.j
            androidx.glance.appwidget.protobuf.Z.e(r1)
            goto L62
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r1)
            r2.j = r0
            r2.m = r6
            com.quizlet.data.interactor.set.c r7 = r0.c
            r7.getClass()
            com.quizlet.remote.model.course.a r6 = new com.quizlet.remote.model.course.a
            r15 = 0
            r12 = r17
            r10 = r19
            r8 = r21
            r14 = r23
            r6.<init>(r7, r8, r10, r12, r14, r15)
            java.lang.Object r1 = r7.c
            kotlinx.coroutines.y r1 = (kotlinx.coroutines.AbstractC5040y) r1
            java.lang.Object r1 = kotlinx.coroutines.E.J(r1, r6, r2)
            if (r1 != r3) goto L61
            goto L7b
        L61:
            r4 = r0
        L62:
            com.quizlet.data.model.d0 r1 = (com.quizlet.data.model.AbstractC4119d0) r1
            r6 = 0
            if (r1 == 0) goto L7f
            androidx.work.impl.model.c r4 = r4.a
            java.lang.Object r4 = r4.b
            com.quizlet.local.ormlite.models.bookmark.a r4 = (com.quizlet.local.ormlite.models.bookmark.a) r4
            io.reactivex.rxjava3.internal.operators.single.g r1 = r4.e(r1)
            r2.j = r6
            r2.m = r5
            java.lang.Object r1 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r1, r2)
            if (r1 != r3) goto L7c
        L7b:
            return r3
        L7c:
            com.quizlet.data.model.d0 r1 = (com.quizlet.data.model.AbstractC4119d0) r1
            return r1
        L7f:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.folder.i.a(long, long, long, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.data.repository.folder.b
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.repository.folder.b r0 = (com.quizlet.data.repository.folder.b) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.repository.folder.b r0 = new com.quizlet.data.repository.folder.b
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r5 = r7.a
            return r5
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            androidx.work.impl.model.c r7 = r4.a
            java.lang.Object r7 = r7.c
            com.quizlet.remote.model.folder.p r7 = (com.quizlet.remote.model.folder.p) r7
            r0.l = r3
            java.lang.Object r5 = r7.a(r5, r0)
            if (r5 != r1) goto L45
            return r1
        L45:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.folder.i.b(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(long r5, java.util.List r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r4 = this;
            boolean r0 = r8 instanceof com.quizlet.data.repository.folder.c
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.data.repository.folder.c r0 = (com.quizlet.data.repository.folder.c) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.repository.folder.c r0 = new com.quizlet.data.repository.folder.c
            r0.<init>(r4, r8)
        L18:
            java.lang.Object r8 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r8)
            kotlin.r r8 = (kotlin.r) r8
            java.lang.Object r5 = r8.a
            return r5
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            androidx.work.impl.model.c r8 = r4.a
            java.lang.Object r8 = r8.c
            com.quizlet.remote.model.folder.p r8 = (com.quizlet.remote.model.folder.p) r8
            r0.l = r3
            java.lang.Object r5 = r8.b(r5, r7, r0)
            if (r5 != r1) goto L45
            return r1
        L45:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.folder.i.c(long, java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.data.repository.folder.e
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.repository.folder.e r0 = (com.quizlet.data.repository.folder.e) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.repository.folder.e r0 = new com.quizlet.data.repository.folder.e
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.data.model.t1 r7 = (com.quizlet.data.model.C4168t1) r7
            java.util.List r5 = r7.a
            goto L45
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            androidx.work.impl.model.c r7 = r4.a
            java.lang.Object r7 = r7.c
            com.quizlet.remote.model.folder.p r7 = (com.quizlet.remote.model.folder.p) r7
            r0.l = r3
            java.io.Serializable r5 = r7.d(r5, r0)
            if (r5 != r1) goto L45
            return r1
        L45:
            java.util.List r5 = (java.util.List) r5
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.folder.i.d(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object e(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.data.repository.folder.f
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.repository.folder.f r0 = (com.quizlet.data.repository.folder.f) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.repository.folder.f r0 = new com.quizlet.data.repository.folder.f
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r5 = r7.a
            return r5
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            androidx.work.impl.model.c r7 = r4.a
            java.lang.Object r7 = r7.c
            com.quizlet.remote.model.folder.p r7 = (com.quizlet.remote.model.folder.p) r7
            r0.l = r3
            java.lang.Object r5 = r7.c(r5, r0)
            if (r5 != r1) goto L45
            return r1
        L45:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.folder.i.e(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object f(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.data.repository.folder.g
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.repository.folder.g r0 = (com.quizlet.data.repository.folder.g) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.repository.folder.g r0 = new com.quizlet.data.repository.folder.g
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r5 = r7.a
            return r5
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            androidx.work.impl.model.c r7 = r4.a
            java.lang.Object r7 = r7.c
            com.quizlet.remote.model.folder.p r7 = (com.quizlet.remote.model.folder.p) r7
            r0.l = r3
            java.lang.Object r5 = r7.e(r5, r0)
            if (r5 != r1) goto L45
            return r1
        L45:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.folder.i.f(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x006d, code lost:
    
        if (r8 == r1) goto L24;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object g(long r6, kotlin.coroutines.jvm.internal.c r8) throws java.lang.Throwable {
        /*
            r5 = this;
            boolean r0 = r8 instanceof com.quizlet.data.repository.folder.h
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.data.repository.folder.h r0 = (com.quizlet.data.repository.folder.h) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.repository.folder.h r0 = new com.quizlet.data.repository.folder.h
            r0.<init>(r5, r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L70
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L32:
            com.quizlet.data.repository.folder.i r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L56
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.j = r5
            r0.m = r4
            com.quizlet.data.interactor.set.c r8 = r5.c
            r8.getClass()
            com.quizlet.remote.model.course.b r2 = new com.quizlet.remote.model.course.b
            r4 = 0
            r2.<init>(r8, r6, r4)
            java.lang.Object r6 = r8.c
            kotlinx.coroutines.y r6 = (kotlinx.coroutines.AbstractC5040y) r6
            java.lang.Object r8 = kotlinx.coroutines.E.J(r6, r2, r0)
            if (r8 != r1) goto L55
            goto L6f
        L55:
            r6 = r5
        L56:
            com.quizlet.data.model.d0 r8 = (com.quizlet.data.model.AbstractC4119d0) r8
            r7 = 0
            if (r8 == 0) goto L73
            androidx.work.impl.model.c r6 = r6.a
            java.lang.Object r6 = r6.b
            com.quizlet.local.ormlite.models.bookmark.a r6 = (com.quizlet.local.ormlite.models.bookmark.a) r6
            io.reactivex.rxjava3.internal.operators.single.g r6 = r6.e(r8)
            r0.j = r7
            r0.m = r3
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r6, r0)
            if (r8 != r1) goto L70
        L6f:
            return r1
        L70:
            com.quizlet.data.model.d0 r8 = (com.quizlet.data.model.AbstractC4119d0) r8
            return r8
        L73:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.folder.i.g(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
