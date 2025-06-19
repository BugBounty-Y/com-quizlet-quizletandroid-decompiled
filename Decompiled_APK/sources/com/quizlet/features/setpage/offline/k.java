package com.quizlet.features.setpage.offline;

import com.google.firebase.messaging.p;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class k {
    public final androidx.work.impl.model.c a;
    public final com.quizlet.featuregate.features.folder.e b;
    public final com.quizlet.offline.managers.b c;
    public final p d;
    public final AbstractC5040y e;
    public final s0 f;
    public final d0 g;

    public k(androidx.work.impl.model.c userProperties, com.quizlet.featuregate.features.folder.e offlineVersionFeature, com.quizlet.offline.managers.b offlineStateManager, p setPageLogger, AbstractC5040y dispatcher) {
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(offlineVersionFeature, "offlineVersionFeature");
        Intrinsics.checkNotNullParameter(offlineStateManager, "offlineStateManager");
        Intrinsics.checkNotNullParameter(setPageLogger, "setPageLogger");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.a = userProperties;
        this.b = offlineVersionFeature;
        this.c = offlineStateManager;
        this.d = setPageLogger;
        this.e = dispatcher;
        this.f = e0.c(com.quizlet.features.setpage.header.data.g.a);
        this.g = e0.b(0, 0, null, 7);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(com.quizlet.features.setpage.offline.k r4, long r5, boolean r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            boolean r0 = r8 instanceof com.quizlet.features.setpage.offline.c
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.features.setpage.offline.c r0 = (com.quizlet.features.setpage.offline.c) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.setpage.offline.c r0 = new com.quizlet.features.setpage.offline.c
            r0.<init>(r4, r8)
        L18:
            java.lang.Object r8 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L4e
        L27:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.offline.managers.b r4 = r4.c
            com.quizlet.offline.managers.i r4 = (com.quizlet.offline.managers.i) r4
            io.reactivex.rxjava3.core.p r4 = r4.c(r5, r7)
            com.quizlet.features.setpage.offline.d r5 = com.quizlet.features.setpage.offline.d.a
            io.reactivex.rxjava3.internal.operators.single.g r4 = r4.g(r5)
            java.lang.String r5 = "map(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r4, r5)
            r0.l = r3
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r4, r0)
            if (r8 != r1) goto L4e
            return r1
        L4e:
            java.lang.String r4 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r4)
            com.quizlet.features.infra.models.b r8 = (com.quizlet.features.infra.models.b) r8
            com.quizlet.features.setpage.header.data.f r4 = new com.quizlet.features.setpage.header.data.f
            r4.<init>(r8)
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.setpage.offline.k.a(com.quizlet.features.setpage.offline.k, long, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:27:0x007a, code lost:
    
        if (r9.emit(r10, r0) == r1) goto L43;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x0094, code lost:
    
        if (r9.emit(r10, r0) == r1) goto L43;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x00bf, code lost:
    
        if (r2.e(r9, r11, r0) == r1) goto L43;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(long r9, boolean r11, kotlin.coroutines.jvm.internal.c r12) throws java.lang.Throwable {
        /*
            r8 = this;
            boolean r0 = r12 instanceof com.quizlet.features.setpage.offline.a
            if (r0 == 0) goto L13
            r0 = r12
            com.quizlet.features.setpage.offline.a r0 = (com.quizlet.features.setpage.offline.a) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.features.setpage.offline.a r0 = new com.quizlet.features.setpage.offline.a
            r0.<init>(r8, r12)
        L18:
            java.lang.Object r12 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 4
            r4 = 3
            r5 = 2
            r6 = 1
            r7 = 0
            if (r2 == 0) goto L4c
            if (r2 == r6) goto L42
            if (r2 == r5) goto L3e
            if (r2 == r4) goto L3a
            if (r2 != r3) goto L32
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto Lc2
        L32:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L97
        L3e:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L7d
        L42:
            boolean r11 = r0.l
            long r9 = r0.k
            com.quizlet.features.setpage.offline.k r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L66
        L4c:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            com.quizlet.features.setpage.offline.b r12 = new com.quizlet.features.setpage.offline.b
            r12.<init>(r8, r7)
            r0.j = r8
            r0.k = r9
            r0.l = r11
            r0.o = r6
            kotlinx.coroutines.y r2 = r8.e
            java.lang.Object r12 = kotlinx.coroutines.E.J(r2, r12, r0)
            if (r12 != r1) goto L65
            goto Lc1
        L65:
            r2 = r8
        L66:
            java.lang.Boolean r12 = (java.lang.Boolean) r12
            boolean r12 = r12.booleanValue()
            if (r12 == 0) goto L80
            kotlinx.coroutines.flow.d0 r9 = r2.g
            com.quizlet.features.setpage.header.data.a r10 = com.quizlet.features.setpage.header.data.a.c
            r0.j = r7
            r0.o = r5
            java.lang.Object r9 = r9.emit(r10, r0)
            if (r9 != r1) goto L7d
            goto Lc1
        L7d:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        L80:
            com.quizlet.offline.managers.b r12 = r2.c
            com.quizlet.offline.managers.i r12 = (com.quizlet.offline.managers.i) r12
            boolean r12 = r12.i
            if (r12 != 0) goto L9a
            kotlinx.coroutines.flow.d0 r9 = r2.g
            com.quizlet.features.setpage.header.data.a r10 = com.quizlet.features.setpage.header.data.a.d
            r0.j = r7
            r0.o = r4
            java.lang.Object r9 = r9.emit(r10, r0)
            if (r9 != r1) goto L97
            goto Lc1
        L97:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        L9a:
            com.google.firebase.messaging.p r12 = r2.d
            java.lang.String r4 = "toggle_set_is_available_offline"
            r12.A(r4)
        La1:
            kotlinx.coroutines.flow.s0 r12 = r2.f
            java.lang.Object r4 = r12.getValue()
            r5 = r4
            com.quizlet.features.setpage.header.data.h r5 = (com.quizlet.features.setpage.header.data.h) r5
            com.quizlet.features.setpage.header.data.f r5 = new com.quizlet.features.setpage.header.data.f
            com.quizlet.features.infra.models.b r6 = com.quizlet.features.infra.models.b.b
            r5.<init>(r6)
            boolean r12 = r12.k(r4, r5)
            if (r12 == 0) goto La1
            r0.j = r7
            r0.o = r3
            java.lang.Object r9 = r2.e(r9, r11, r0)
            if (r9 != r1) goto Lc2
        Lc1:
            return r1
        Lc2:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.setpage.offline.k.b(long, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0067 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0068  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0072  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0075  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:18:0x0068 -> B:19:0x006a). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(long r11, boolean r13, kotlin.coroutines.jvm.internal.c r14) throws java.lang.Throwable {
        /*
            r10 = this;
            boolean r0 = r14 instanceof com.quizlet.features.setpage.offline.f
            if (r0 == 0) goto L13
            r0 = r14
            com.quizlet.features.setpage.offline.f r0 = (com.quizlet.features.setpage.offline.f) r0
            int r1 = r0.q
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.q = r1
            goto L18
        L13:
            com.quizlet.features.setpage.offline.f r0 = new com.quizlet.features.setpage.offline.f
            r0.<init>(r10, r14)
        L18:
            java.lang.Object r14 = r0.o
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.q
            r3 = 1
            if (r2 == 0) goto L3b
            if (r2 != r3) goto L33
            boolean r11 = r0.n
            long r12 = r0.m
            java.lang.Object r2 = r0.l
            kotlinx.coroutines.flow.s0 r4 = r0.k
            com.quizlet.features.setpage.offline.k r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r14)
            r8 = r11
            r6 = r12
            goto L6a
        L33:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L3b:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            kotlinx.coroutines.flow.s0 r14 = r10.f
            r5 = r10
            r6 = r11
            r8 = r13
        L43:
            java.lang.Object r2 = r14.getValue()
            r11 = r2
            com.quizlet.features.setpage.header.data.h r11 = (com.quizlet.features.setpage.header.data.h) r11
            r0.j = r5
            r0.k = r14
            r0.l = r2
            r0.m = r6
            r0.n = r8
            r0.q = r3
            r5.getClass()
            com.quizlet.features.setpage.offline.e r4 = new com.quizlet.features.setpage.offline.e
            r9 = 0
            r4.<init>(r5, r6, r8, r9)
            kotlinx.coroutines.y r11 = r5.e
            java.lang.Object r11 = kotlinx.coroutines.E.J(r11, r4, r0)
            if (r11 != r1) goto L68
            return r1
        L68:
            r4 = r14
            r14 = r11
        L6a:
            com.quizlet.features.setpage.header.data.h r14 = (com.quizlet.features.setpage.header.data.h) r14
            boolean r11 = r4.k(r2, r14)
            if (r11 == 0) goto L75
            kotlin.Unit r11 = kotlin.Unit.a
            return r11
        L75:
            r14 = r4
            goto L43
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.setpage.offline.k.c(long, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x0062, code lost:
    
        if (r10.emit(r11, r0) == r1) goto L39;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x00b5, code lost:
    
        if (r10.emit(r11, r0) != r1) goto L40;
     */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00a9 A[PHI: r10
  0x00a9: PHI (r10v6 com.quizlet.features.setpage.offline.k) = (r10v5 com.quizlet.features.setpage.offline.k), (r10v12 com.quizlet.features.setpage.offline.k) binds: [B:35:0x00a6, B:17:0x003a] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(long r10, boolean r12, boolean r13, kotlin.coroutines.jvm.internal.c r14) {
        /*
            r9 = this;
            boolean r0 = r14 instanceof com.quizlet.features.setpage.offline.g
            if (r0 == 0) goto L13
            r0 = r14
            com.quizlet.features.setpage.offline.g r0 = (com.quizlet.features.setpage.offline.g) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.features.setpage.offline.g r0 = new com.quizlet.features.setpage.offline.g
            r0.<init>(r9, r14)
        L18:
            java.lang.Object r14 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 0
            r4 = 4
            r5 = 3
            r6 = 2
            r7 = 1
            if (r2 == 0) goto L53
            if (r2 == r7) goto L4f
            if (r2 == r6) goto L41
            if (r2 == r5) goto L3a
            if (r2 != r4) goto L32
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto Lb8
        L32:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L3a:
            com.quizlet.features.setpage.offline.k r10 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto La9
        L41:
            boolean r12 = r0.l
            long r10 = r0.k
            com.quizlet.features.setpage.offline.k r13 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r14)
            r8 = r13
            r13 = r12
            r11 = r10
            r10 = r8
            goto L9e
        L4f:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto L65
        L53:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            if (r13 != 0) goto L68
            kotlinx.coroutines.flow.d0 r10 = r9.g
            com.quizlet.features.setpage.header.data.i r11 = com.quizlet.features.setpage.header.data.i.b
            r0.o = r7
            java.lang.Object r10 = r10.emit(r11, r0)
            if (r10 != r1) goto L65
            goto Lb7
        L65:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        L68:
            com.google.firebase.messaging.p r13 = r9.d
            java.lang.String r14 = "toggle_set_is_not_available_offline"
            r13.A(r14)
        L6f:
            kotlinx.coroutines.flow.s0 r13 = r9.f
            java.lang.Object r14 = r13.getValue()
            r2 = r14
            com.quizlet.features.setpage.header.data.h r2 = (com.quizlet.features.setpage.header.data.h) r2
            com.quizlet.features.setpage.header.data.f r2 = new com.quizlet.features.setpage.header.data.f
            com.quizlet.features.infra.models.b r7 = com.quizlet.features.infra.models.b.b
            r2.<init>(r7)
            boolean r13 = r13.k(r14, r2)
            if (r13 == 0) goto L6f
            com.quizlet.features.setpage.offline.h r13 = new com.quizlet.features.setpage.offline.h
            r13.<init>(r9, r10, r3)
            r0.j = r9
            r0.k = r10
            r0.l = r12
            r0.o = r6
            kotlinx.coroutines.y r14 = r9.e
            java.lang.Object r13 = kotlinx.coroutines.E.J(r14, r13, r0)
            if (r13 != r1) goto L9b
            goto Lb7
        L9b:
            r13 = r12
            r11 = r10
            r10 = r9
        L9e:
            r0.j = r10
            r0.o = r5
            java.lang.Object r11 = r10.c(r11, r13, r0)
            if (r11 != r1) goto La9
            goto Lb7
        La9:
            kotlinx.coroutines.flow.d0 r10 = r10.g
            com.quizlet.features.setpage.header.data.i r11 = com.quizlet.features.setpage.header.data.i.a
            r0.j = r3
            r0.o = r4
            java.lang.Object r10 = r10.emit(r11, r0)
            if (r10 != r1) goto Lb8
        Lb7:
            return r1
        Lb8:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.setpage.offline.k.d(long, boolean, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:39:0x0092, code lost:
    
        if (r12.emit(r2, r0) != r1) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x00c9, code lost:
    
        if (r9.emit(r10, r0) == r1) goto L48;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0083  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0084 A[Catch: Exception -> 0x0043, PHI: r9 r11
  0x0084: PHI (r9v8 long) = (r9v7 long), (r9v11 long) binds: [B:36:0x0081, B:23:0x0049] A[DONT_GENERATE, DONT_INLINE]
  0x0084: PHI (r11v5 com.quizlet.features.setpage.offline.k) = (r11v4 com.quizlet.features.setpage.offline.k), (r11v9 com.quizlet.features.setpage.offline.k) binds: [B:36:0x0081, B:23:0x0049] A[DONT_GENERATE, DONT_INLINE], TRY_LEAVE, TryCatch #2 {Exception -> 0x0043, blocks: (B:18:0x003e, B:23:0x0049, B:38:0x0084, B:35:0x0077), top: B:55:0x0023 }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r11v2 */
    /* JADX WARN: Type inference failed for: r11v7 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object e(long r9, boolean r11, kotlin.coroutines.jvm.internal.c r12) {
        /*
            Method dump skipped, instructions count: 207
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.setpage.offline.k.e(long, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
