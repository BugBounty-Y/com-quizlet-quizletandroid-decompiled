package com.quizlet.data.interactor.folderstudymaterial;

import androidx.datastore.core.C1087t;
import androidx.paging.J0;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class o {
    public final com.quizlet.remote.model.folderstudymaterial.m a;
    public final androidx.work.impl.model.e b;
    public final org.slf4j.b c;

    public o(com.quizlet.remote.model.folderstudymaterial.m folderStudyMaterialsRepository, androidx.work.impl.model.e cache, org.slf4j.b logger) {
        Intrinsics.checkNotNullParameter(folderStudyMaterialsRepository, "folderStudyMaterialsRepository");
        Intrinsics.checkNotNullParameter(cache, "cache");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.a = folderStudyMaterialsRepository;
        this.b = cache;
        this.c = logger;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(com.quizlet.data.interactor.folderstudymaterial.o r9, long r10, java.util.List r12, kotlin.coroutines.jvm.internal.c r13) {
        /*
            r9.getClass()
            boolean r0 = r13 instanceof com.quizlet.data.interactor.folderstudymaterial.k
            if (r0 == 0) goto L16
            r0 = r13
            com.quizlet.data.interactor.folderstudymaterial.k r0 = (com.quizlet.data.interactor.folderstudymaterial.k) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.o = r1
            goto L1b
        L16:
            com.quizlet.data.interactor.folderstudymaterial.k r0 = new com.quizlet.data.interactor.folderstudymaterial.k
            r0.<init>(r9, r13)
        L1b:
            java.lang.Object r13 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 0
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L4e
            if (r2 == r5) goto L3f
            if (r2 != r4) goto L37
            long r9 = r0.l
            java.lang.Object r11 = r0.k
            java.lang.Exception r11 = (java.lang.Exception) r11
            com.quizlet.data.interactor.folderstudymaterial.o r12 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto La8
        L37:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L3f:
            long r10 = r0.l
            java.lang.Object r9 = r0.k
            r12 = r9
            java.util.List r12 = (java.util.List) r12
            com.quizlet.data.interactor.folderstudymaterial.o r9 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r13)     // Catch: java.lang.Exception -> L4c
            goto L7d
        L4c:
            r13 = move-exception
            goto L80
        L4e:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            androidx.work.impl.model.e r13 = r9.b     // Catch: java.lang.Exception -> L4c
            java.lang.String r2 = b(r10, r12)     // Catch: java.lang.Exception -> L4c
            java.lang.String r6 = "key"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r6)     // Catch: java.lang.Exception -> L4c
            java.lang.Object r6 = r13.c     // Catch: java.lang.Exception -> L4c
            androidx.datastore.core.h r6 = (androidx.datastore.core.InterfaceC1076h) r6     // Catch: java.lang.Exception -> L4c
            kotlinx.coroutines.flow.i r6 = r6.getData()     // Catch: java.lang.Exception -> L4c
            com.quizlet.features.folders.addtofolder.viewmodel.usecase.c r7 = new com.quizlet.features.folders.addtofolder.viewmodel.usecase.c     // Catch: java.lang.Exception -> L4c
            r8 = 1
            r7.<init>(r6, r2, r13, r8)     // Catch: java.lang.Exception -> L4c
            kotlinx.coroutines.flow.i r13 = kotlinx.coroutines.flow.e0.m(r7)     // Catch: java.lang.Exception -> L4c
            r0.j = r9     // Catch: java.lang.Exception -> L4c
            r0.k = r12     // Catch: java.lang.Exception -> L4c
            r0.l = r10     // Catch: java.lang.Exception -> L4c
            r0.o = r5     // Catch: java.lang.Exception -> L4c
            java.lang.Object r13 = kotlinx.coroutines.flow.e0.r(r13, r0)     // Catch: java.lang.Exception -> L4c
            if (r13 != r1) goto L7d
            goto Lbc
        L7d:
            java.util.List r13 = (java.util.List) r13     // Catch: java.lang.Exception -> L4c
            return r13
        L80:
            androidx.work.impl.model.e r2 = r9.b
            java.lang.String r12 = b(r10, r12)
            r0.j = r9
            r0.k = r13
            r0.l = r10
            r0.o = r4
            com.quizlet.local.cache.b r4 = new com.quizlet.local.cache.b
            r4.<init>(r12, r3)
            java.lang.Object r12 = r2.c
            androidx.datastore.core.h r12 = (androidx.datastore.core.InterfaceC1076h) r12
            java.lang.Object r12 = com.google.android.gms.internal.mlkit_vision_barcode.S6.d(r12, r4, r0)
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            if (r12 != r0) goto La0
            goto La2
        La0:
            kotlin.Unit r12 = kotlin.Unit.a
        La2:
            if (r12 != r1) goto La5
            goto Lbc
        La5:
            r12 = r9
            r9 = r10
            r11 = r13
        La8:
            org.slf4j.b r12 = r12.c
            java.lang.StringBuilder r13 = new java.lang.StringBuilder
            java.lang.String r0 = "Failed to get cache for folderId="
            r13.<init>(r0)
            r13.append(r9)
            java.lang.String r9 = r13.toString()
            r12.c(r9, r11)
            r1 = r3
        Lbc:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.folderstudymaterial.o.a(com.quizlet.data.interactor.folderstudymaterial.o, long, java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static String b(long j, List filterByType) {
        Intrinsics.checkNotNullParameter(filterByType, "filterByType");
        return "GetFolderStudyMaterialsUseCaseKey(folderId=" + j + ", filterByType=" + filterByType + ")";
    }

    public final J0 c(long j, List filterByType) {
        Intrinsics.checkNotNullParameter(filterByType, "filterByType");
        return new J0(new n(this, j, filterByType, null), new J0(new C1087t(new l(this, j, filterByType, null)), new m(this, j, filterByType, null), 5));
    }
}
