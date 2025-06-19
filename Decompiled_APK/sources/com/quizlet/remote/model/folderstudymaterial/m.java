package com.quizlet.remote.model.folderstudymaterial;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m {
    public final j a;
    public final c b;
    public final com.quizlet.quizletandroid.ui.login.di.a c;
    public final com.quizlet.remote.model.base.b d;

    public m(j dataSource, c responseMapper, com.quizlet.quizletandroid.ui.login.di.a folderStudyMaterialMapper, com.quizlet.remote.model.base.b pagingInfoMapper) {
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(responseMapper, "responseMapper");
        Intrinsics.checkNotNullParameter(folderStudyMaterialMapper, "folderStudyMaterialMapper");
        Intrinsics.checkNotNullParameter(pagingInfoMapper, "pagingInfoMapper");
        this.a = dataSource;
        this.b = responseMapper;
        this.c = folderStudyMaterialMapper;
        this.d = pagingInfoMapper;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(long r11, java.util.List r13, com.quizlet.data.model.J0 r14, kotlin.coroutines.jvm.internal.c r15) {
        /*
            r10 = this;
            boolean r0 = r15 instanceof com.quizlet.remote.model.folderstudymaterial.k
            if (r0 == 0) goto L14
            r0 = r15
            com.quizlet.remote.model.folderstudymaterial.k r0 = (com.quizlet.remote.model.folderstudymaterial.k) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.m = r1
        L12:
            r8 = r0
            goto L1a
        L14:
            com.quizlet.remote.model.folderstudymaterial.k r0 = new com.quizlet.remote.model.folderstudymaterial.k
            r0.<init>(r10, r15)
            goto L12
        L1a:
            java.lang.Object r15 = r8.k
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.m
            r9 = 0
            r2 = 1
            if (r1 == 0) goto L38
            if (r1 != r2) goto L30
            com.quizlet.remote.model.folderstudymaterial.m r11 = r8.j
            androidx.glance.appwidget.protobuf.Z.e(r15)
            kotlin.r r15 = (kotlin.r) r15
            java.lang.Object r12 = r15.a
            goto L56
        L30:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r15)
            if (r14 == 0) goto L43
            com.quizlet.remote.model.base.PagingInfo r14 = com.quizlet.remote.model.base.b.b(r14)
            r7 = r14
            goto L44
        L43:
            r7 = r9
        L44:
            r8.j = r10
            r8.m = r2
            com.quizlet.remote.model.folderstudymaterial.j r1 = r10.a
            r5 = 1
            r6 = 1
            r2 = r11
            r4 = r13
            java.lang.Object r12 = r1.b(r2, r4, r5, r6, r7, r8)
            if (r12 != r0) goto L55
            return r0
        L55:
            r11 = r10
        L56:
            kotlin.p r13 = kotlin.r.b
            boolean r13 = r12 instanceof kotlin.q
            if (r13 != 0) goto L73
            com.quizlet.remote.model.folderstudymaterial.FolderStudyMaterialResponse r12 = (com.quizlet.remote.model.folderstudymaterial.FolderStudyMaterialResponse) r12
            com.quizlet.remote.model.base.PagingInfo r13 = r12.a
            if (r13 == 0) goto L68
            com.quizlet.remote.model.base.b r14 = r11.d
            com.quizlet.data.model.J0 r9 = com.quizlet.remote.model.base.b.a(r13)
        L68:
            com.quizlet.remote.model.folderstudymaterial.c r11 = r11.b
            java.util.ArrayList r11 = r11.c(r12)
            com.quizlet.data.model.N r12 = new com.quizlet.data.model.N
            r12.<init>(r11, r9)
        L73:
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.folderstudymaterial.m.a(long, java.util.List, com.quizlet.data.model.J0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(com.quizlet.generated.enums.y1 r8, java.lang.Long r9, java.lang.String r10, com.quizlet.data.model.J0 r11, kotlin.coroutines.jvm.internal.c r12) {
        /*
            r7 = this;
            boolean r0 = r12 instanceof com.quizlet.remote.model.folderstudymaterial.l
            if (r0 == 0) goto L14
            r0 = r12
            com.quizlet.remote.model.folderstudymaterial.l r0 = (com.quizlet.remote.model.folderstudymaterial.l) r0
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
            com.quizlet.remote.model.folderstudymaterial.l r0 = new com.quizlet.remote.model.folderstudymaterial.l
            r0.<init>(r7, r12)
            goto L12
        L1a:
            java.lang.Object r12 = r6.k
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.m
            r2 = 1
            if (r1 == 0) goto L37
            if (r1 != r2) goto L2f
            com.quizlet.remote.model.folderstudymaterial.m r8 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            kotlin.r r12 = (kotlin.r) r12
            java.lang.Object r9 = r12.a
            goto L55
        L2f:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            if (r11 == 0) goto L42
            com.quizlet.remote.model.base.PagingInfo r11 = com.quizlet.remote.model.base.b.b(r11)
        L40:
            r5 = r11
            goto L44
        L42:
            r11 = 0
            goto L40
        L44:
            r6.j = r7
            r6.m = r2
            com.quizlet.remote.model.folderstudymaterial.j r1 = r7.a
            r2 = r8
            r3 = r9
            r4 = r10
            java.lang.Object r9 = r1.d(r2, r3, r4, r5, r6)
            if (r9 != r0) goto L54
            return r0
        L54:
            r8 = r7
        L55:
            kotlin.p r10 = kotlin.r.b
            boolean r10 = r9 instanceof kotlin.q
            if (r10 != 0) goto L6e
            com.quizlet.remote.model.folderstudymaterial.FolderStudyMaterialResponse r9 = (com.quizlet.remote.model.folderstudymaterial.FolderStudyMaterialResponse) r9
            com.quizlet.quizletandroid.ui.login.di.a r8 = r8.c
            com.quizlet.remote.model.folderstudymaterial.FolderStudyMaterialResponse$Models r9 = r9.d
            if (r9 == 0) goto L67
            java.util.List r9 = r9.a
            if (r9 != 0) goto L69
        L67:
            kotlin.collections.K r9 = kotlin.collections.K.a
        L69:
            java.util.ArrayList r8 = com.google.android.gms.internal.mlkit_vision_barcode.S.f(r8, r9)
            return r8
        L6e:
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.folderstudymaterial.m.b(com.quizlet.generated.enums.y1, java.lang.Long, java.lang.String, com.quizlet.data.model.J0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
