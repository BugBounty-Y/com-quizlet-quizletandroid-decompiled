package com.quizlet.remote.model.folderstudymaterial;

import com.quizlet.remote.service.o;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes3.dex */
public final class j {
    public final o a;
    public final AbstractC5040y b;

    public j(o service, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = service;
        this.b = ioDispatcher;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(java.util.ArrayList r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r6 = this;
            boolean r0 = r8 instanceof com.quizlet.remote.model.folderstudymaterial.d
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.remote.model.folderstudymaterial.d r0 = (com.quizlet.remote.model.folderstudymaterial.d) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.remote.model.folderstudymaterial.d r0 = new com.quizlet.remote.model.folderstudymaterial.d
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            com.quizlet.qutils.android.f r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)     // Catch: java.lang.Exception -> L29
            goto L52
        L29:
            r7 = move-exception
            goto L59
        L2b:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.qutils.android.f r8 = new com.quizlet.qutils.android.f
            r2 = 10
            r8.<init>(r2)
            com.quizlet.remote.service.o r2 = r6.a     // Catch: java.lang.Exception -> L29
            com.quizlet.remote.model.base.ApiPostBody r4 = new com.quizlet.remote.model.base.ApiPostBody     // Catch: java.lang.Exception -> L29
            r4.<init>(r7)     // Catch: java.lang.Exception -> L29
            r0.j = r8     // Catch: java.lang.Exception -> L29
            r0.m = r3     // Catch: java.lang.Exception -> L29
            java.lang.Object r7 = r2.d(r4, r0)     // Catch: java.lang.Exception -> L29
            if (r7 != r1) goto L4f
            return r1
        L4f:
            r5 = r8
            r8 = r7
            r7 = r5
        L52:
            com.quizlet.remote.model.base.ApiThreeWrapper r8 = (com.quizlet.remote.model.base.ApiThreeWrapper) r8     // Catch: java.lang.Exception -> L29
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_barcode.V.c(r8, r7)     // Catch: java.lang.Exception -> L29
            return r7
        L59:
            kotlin.p r8 = kotlin.r.b
            kotlin.q r7 = androidx.glance.appwidget.protobuf.Z.b(r7)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.folderstudymaterial.j.a(java.util.ArrayList, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(long r13, java.util.List r15, boolean r16, boolean r17, com.quizlet.remote.model.base.PagingInfo r18, kotlin.coroutines.jvm.internal.c r19) throws java.lang.Throwable {
        /*
            r12 = this;
            r0 = r19
            boolean r2 = r0 instanceof com.quizlet.remote.model.folderstudymaterial.e
            if (r2 == 0) goto L16
            r2 = r0
            com.quizlet.remote.model.folderstudymaterial.e r2 = (com.quizlet.remote.model.folderstudymaterial.e) r2
            int r3 = r2.l
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L16
            int r3 = r3 - r4
            r2.l = r3
        L14:
            r9 = r2
            goto L1c
        L16:
            com.quizlet.remote.model.folderstudymaterial.e r2 = new com.quizlet.remote.model.folderstudymaterial.e
            r2.<init>(r12, r0)
            goto L14
        L1c:
            java.lang.Object r0 = r9.j
            kotlin.coroutines.intrinsics.a r10 = kotlin.coroutines.intrinsics.a.a
            int r2 = r9.l
            r11 = 1
            if (r2 == 0) goto L33
            if (r2 != r11) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r0)
            goto L50
        L2b:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r2)
            throw r0
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            com.quizlet.remote.model.folderstudymaterial.f r0 = new com.quizlet.remote.model.folderstudymaterial.f
            r8 = 0
            r1 = r12
            r2 = r13
            r4 = r15
            r5 = r16
            r6 = r17
            r7 = r18
            r0.<init>(r1, r2, r4, r5, r6, r7, r8)
            r9.l = r11
            kotlinx.coroutines.y r2 = r12.b
            java.lang.Object r0 = kotlinx.coroutines.E.J(r2, r0, r9)
            if (r0 != r10) goto L50
            return r10
        L50:
            kotlin.r r0 = (kotlin.r) r0
            java.lang.Object r0 = r0.a
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.folderstudymaterial.j.b(long, java.util.List, boolean, boolean, com.quizlet.remote.model.base.PagingInfo, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(java.lang.String r6, com.quizlet.generated.enums.y1 r7, java.lang.Long r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r5 = this;
            boolean r0 = r9 instanceof com.quizlet.remote.model.folderstudymaterial.g
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.remote.model.folderstudymaterial.g r0 = (com.quizlet.remote.model.folderstudymaterial.g) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.remote.model.folderstudymaterial.g r0 = new com.quizlet.remote.model.folderstudymaterial.g
            r0.<init>(r5, r9)
        L18:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            com.quizlet.remote.model.base.a r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Exception -> L29
            goto L4c
        L29:
            r6 = move-exception
            goto L53
        L2b:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.quizlet.remote.model.base.a r9 = com.quizlet.remote.model.base.a.a
            com.quizlet.remote.service.o r2 = r5.a     // Catch: java.lang.Exception -> L29
            int r7 = r7.b()     // Catch: java.lang.Exception -> L29
            r0.j = r9     // Catch: java.lang.Exception -> L29
            r0.m = r3     // Catch: java.lang.Exception -> L29
            java.lang.Object r6 = r2.a(r6, r7, r8, r0)     // Catch: java.lang.Exception -> L29
            if (r6 != r1) goto L49
            return r1
        L49:
            r4 = r9
            r9 = r6
            r6 = r4
        L4c:
            com.quizlet.remote.model.base.ApiThreeWrapper r9 = (com.quizlet.remote.model.base.ApiThreeWrapper) r9     // Catch: java.lang.Exception -> L29
            java.lang.Object r6 = com.google.android.gms.internal.mlkit_vision_barcode.V.c(r9, r6)     // Catch: java.lang.Exception -> L29
            return r6
        L53:
            kotlin.p r7 = kotlin.r.b
            kotlin.q r6 = androidx.glance.appwidget.protobuf.Z.b(r6)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.folderstudymaterial.j.c(java.lang.String, com.quizlet.generated.enums.y1, java.lang.Long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(com.quizlet.generated.enums.y1 r10, java.lang.Long r11, java.lang.String r12, com.quizlet.remote.model.base.PagingInfo r13, kotlin.coroutines.jvm.internal.c r14) {
        /*
            r9 = this;
            boolean r0 = r14 instanceof com.quizlet.remote.model.folderstudymaterial.h
            if (r0 == 0) goto L14
            r0 = r14
            com.quizlet.remote.model.folderstudymaterial.h r0 = (com.quizlet.remote.model.folderstudymaterial.h) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.m = r1
        L12:
            r6 = r0
            goto L1a
        L14:
            com.quizlet.remote.model.folderstudymaterial.h r0 = new com.quizlet.remote.model.folderstudymaterial.h
            r0.<init>(r9, r14)
            goto L12
        L1a:
            java.lang.Object r14 = r6.k
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.m
            r2 = 1
            if (r1 == 0) goto L36
            if (r1 != r2) goto L2e
            com.quizlet.remote.model.base.a r10 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r14)     // Catch: java.lang.Exception -> L2b
            goto L70
        L2b:
            r0 = move-exception
            r10 = r0
            goto L77
        L2e:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            com.quizlet.remote.model.base.a r14 = com.quizlet.remote.model.base.a.a
            com.quizlet.remote.service.o r1 = r9.a     // Catch: java.lang.Exception -> L2b
            int r10 = r10.b()     // Catch: java.lang.Exception -> L2b
            java.util.LinkedHashMap r5 = new java.util.LinkedHashMap     // Catch: java.lang.Exception -> L2b
            r5.<init>()     // Catch: java.lang.Exception -> L2b
            kotlin.Pair r3 = new kotlin.Pair     // Catch: java.lang.Exception -> L2b
            java.lang.String r4 = "filters[isDeleted]"
            java.lang.String r7 = "false"
            r3.<init>(r4, r7)     // Catch: java.lang.Exception -> L2b
            java.util.Map r3 = kotlin.collections.U.b(r3)     // Catch: java.lang.Exception -> L2b
            r5.putAll(r3)     // Catch: java.lang.Exception -> L2b
            if (r13 == 0) goto L5f
            java.util.LinkedHashMap r13 = r13.a()     // Catch: java.lang.Exception -> L2b
            r5.putAll(r13)     // Catch: java.lang.Exception -> L2b
        L5f:
            r6.j = r14     // Catch: java.lang.Exception -> L2b
            r6.m = r2     // Catch: java.lang.Exception -> L2b
            r2 = r10
            r4 = r11
            r3 = r12
            java.lang.Object r10 = r1.c(r2, r3, r4, r5, r6)     // Catch: java.lang.Exception -> L2b
            if (r10 != r0) goto L6d
            return r0
        L6d:
            r8 = r14
            r14 = r10
            r10 = r8
        L70:
            com.quizlet.remote.model.base.ApiThreeWrapper r14 = (com.quizlet.remote.model.base.ApiThreeWrapper) r14     // Catch: java.lang.Exception -> L2b
            java.lang.Object r10 = com.google.android.gms.internal.mlkit_vision_barcode.V.c(r14, r10)     // Catch: java.lang.Exception -> L2b
            return r10
        L77:
            kotlin.p r11 = kotlin.r.b
            kotlin.q r10 = androidx.glance.appwidget.protobuf.Z.b(r10)
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.folderstudymaterial.j.d(com.quizlet.generated.enums.y1, java.lang.Long, java.lang.String, com.quizlet.remote.model.base.PagingInfo, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object e(java.util.ArrayList r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r6 = this;
            boolean r0 = r8 instanceof com.quizlet.remote.model.folderstudymaterial.i
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.remote.model.folderstudymaterial.i r0 = (com.quizlet.remote.model.folderstudymaterial.i) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.remote.model.folderstudymaterial.i r0 = new com.quizlet.remote.model.folderstudymaterial.i
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            com.quizlet.qutils.android.f r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)     // Catch: java.lang.Exception -> L29
            goto L52
        L29:
            r7 = move-exception
            goto L59
        L2b:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.qutils.android.f r8 = new com.quizlet.qutils.android.f
            r2 = 9
            r8.<init>(r2)
            com.quizlet.remote.service.o r2 = r6.a     // Catch: java.lang.Exception -> L29
            com.quizlet.remote.model.base.ApiPostBody r4 = new com.quizlet.remote.model.base.ApiPostBody     // Catch: java.lang.Exception -> L29
            r4.<init>(r7)     // Catch: java.lang.Exception -> L29
            r0.j = r8     // Catch: java.lang.Exception -> L29
            r0.m = r3     // Catch: java.lang.Exception -> L29
            java.lang.Object r7 = r2.b(r4, r0)     // Catch: java.lang.Exception -> L29
            if (r7 != r1) goto L4f
            return r1
        L4f:
            r5 = r8
            r8 = r7
            r7 = r5
        L52:
            com.quizlet.remote.model.base.ApiThreeWrapper r8 = (com.quizlet.remote.model.base.ApiThreeWrapper) r8     // Catch: java.lang.Exception -> L29
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_barcode.V.c(r8, r7)     // Catch: java.lang.Exception -> L29
            return r7
        L59:
            kotlin.p r8 = kotlin.r.b
            kotlin.q r7 = androidx.glance.appwidget.protobuf.Z.b(r7)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.folderstudymaterial.j.e(java.util.ArrayList, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
