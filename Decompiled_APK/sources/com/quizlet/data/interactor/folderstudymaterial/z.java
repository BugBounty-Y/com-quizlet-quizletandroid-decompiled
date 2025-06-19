package com.quizlet.data.interactor.folderstudymaterial;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class z {
    public final com.google.firebase.crashlytics.internal.settings.b a;
    public final com.quizlet.data.interactor.achievements.f b;

    public z(com.google.firebase.crashlytics.internal.settings.b addStudyMaterialToFolderUseCase, com.quizlet.data.interactor.achievements.f deleteStudyMaterialFromFolderUseCase, com.google.firebase.perf.logging.b mapper) {
        Intrinsics.checkNotNullParameter(addStudyMaterialToFolderUseCase, "addStudyMaterialToFolderUseCase");
        Intrinsics.checkNotNullParameter(deleteStudyMaterialFromFolderUseCase, "deleteStudyMaterialFromFolderUseCase");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.a = addStudyMaterialToFolderUseCase;
        this.b = deleteStudyMaterialFromFolderUseCase;
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x00a0 A[Catch: all -> 0x0037, TryCatch #0 {all -> 0x0037, blocks: (B:13:0x002e, B:40:0x00b4, B:45:0x00c1, B:43:0x00bb, B:20:0x004c, B:29:0x0088, B:34:0x009a, B:36:0x00a0, B:44:0x00bc, B:32:0x0093, B:23:0x0057, B:25:0x0073, B:33:0x0094), top: B:49:0x0020 }] */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00ba  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00bb A[Catch: all -> 0x0037, TryCatch #0 {all -> 0x0037, blocks: (B:13:0x002e, B:40:0x00b4, B:45:0x00c1, B:43:0x00bb, B:20:0x004c, B:29:0x0088, B:34:0x009a, B:36:0x00a0, B:44:0x00bc, B:32:0x0093, B:23:0x0057, B:25:0x0073, B:33:0x0094), top: B:49:0x0020 }] */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00bc A[Catch: all -> 0x0037, TryCatch #0 {all -> 0x0037, blocks: (B:13:0x002e, B:40:0x00b4, B:45:0x00c1, B:43:0x00bb, B:20:0x004c, B:29:0x0088, B:34:0x009a, B:36:0x00a0, B:44:0x00bc, B:32:0x0093, B:23:0x0057, B:25:0x0073, B:33:0x0094), top: B:49:0x0020 }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(java.util.ArrayList r7, java.util.ArrayList r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            Method dump skipped, instructions count: 206
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.folderstudymaterial.z.a(java.util.ArrayList, java.util.ArrayList, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(com.quizlet.data.model.I1 r7, java.util.List r8, java.util.List r9, kotlin.coroutines.jvm.internal.c r10) {
        /*
            r6 = this;
            boolean r0 = r10 instanceof com.quizlet.data.interactor.folderstudymaterial.x
            if (r0 == 0) goto L13
            r0 = r10
            com.quizlet.data.interactor.folderstudymaterial.x r0 = (com.quizlet.data.interactor.folderstudymaterial.x) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folderstudymaterial.x r0 = new com.quizlet.data.interactor.folderstudymaterial.x
            r0.<init>(r6, r10)
        L18:
            java.lang.Object r10 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r10)
            kotlin.r r10 = (kotlin.r) r10
            java.lang.Object r7 = r10.a
            return r7
        L2b:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            java.util.ArrayList r10 = new java.util.ArrayList
            r2 = 10
            int r4 = kotlin.collections.C.q(r8, r2)
            r10.<init>(r4)
            java.util.Iterator r8 = r8.iterator()
        L45:
            boolean r4 = r8.hasNext()
            if (r4 == 0) goto L5d
            java.lang.Object r4 = r8.next()
            java.lang.Number r4 = (java.lang.Number) r4
            long r4 = r4.longValue()
            com.quizlet.data.model.g0 r4 = com.google.firebase.perf.logging.b.l(r7, r4)
            r10.add(r4)
            goto L45
        L5d:
            java.util.ArrayList r8 = new java.util.ArrayList
            int r2 = kotlin.collections.C.q(r9, r2)
            r8.<init>(r2)
            java.util.Iterator r9 = r9.iterator()
        L6a:
            boolean r2 = r9.hasNext()
            if (r2 == 0) goto L82
            java.lang.Object r2 = r9.next()
            java.lang.Number r2 = (java.lang.Number) r2
            long r4 = r2.longValue()
            com.quizlet.data.model.g0 r2 = com.google.firebase.perf.logging.b.l(r7, r4)
            r8.add(r2)
            goto L6a
        L82:
            r0.l = r3
            java.lang.Object r7 = r6.a(r10, r8, r0)
            if (r7 != r1) goto L8b
            return r1
        L8b:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.folderstudymaterial.z.b(com.quizlet.data.model.I1, java.util.List, java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(long r6, java.util.ArrayList r8, java.util.ArrayList r9, kotlin.coroutines.jvm.internal.c r10) {
        /*
            r5 = this;
            boolean r0 = r10 instanceof com.quizlet.data.interactor.folderstudymaterial.y
            if (r0 == 0) goto L13
            r0 = r10
            com.quizlet.data.interactor.folderstudymaterial.y r0 = (com.quizlet.data.interactor.folderstudymaterial.y) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folderstudymaterial.y r0 = new com.quizlet.data.interactor.folderstudymaterial.y
            r0.<init>(r5, r10)
        L18:
            java.lang.Object r10 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r10)
            kotlin.r r10 = (kotlin.r) r10
            java.lang.Object r6 = r10.a
            return r6
        L2b:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            java.util.ArrayList r10 = new java.util.ArrayList
            r2 = 10
            int r4 = kotlin.collections.C.q(r8, r2)
            r10.<init>(r4)
            java.util.Iterator r8 = r8.iterator()
        L45:
            boolean r4 = r8.hasNext()
            if (r4 == 0) goto L59
            java.lang.Object r4 = r8.next()
            com.quizlet.data.model.M1 r4 = (com.quizlet.data.model.M1) r4
            com.quizlet.data.model.g0 r4 = com.google.firebase.perf.logging.b.l(r4, r6)
            r10.add(r4)
            goto L45
        L59:
            java.util.ArrayList r8 = new java.util.ArrayList
            int r2 = kotlin.collections.C.q(r9, r2)
            r8.<init>(r2)
            java.util.Iterator r9 = r9.iterator()
        L66:
            boolean r2 = r9.hasNext()
            if (r2 == 0) goto L7a
            java.lang.Object r2 = r9.next()
            com.quizlet.data.model.M1 r2 = (com.quizlet.data.model.M1) r2
            com.quizlet.data.model.g0 r2 = com.google.firebase.perf.logging.b.l(r2, r6)
            r8.add(r2)
            goto L66
        L7a:
            r0.l = r3
            java.lang.Object r6 = r5.a(r10, r8, r0)
            if (r6 != r1) goto L83
            return r1
        L83:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.folderstudymaterial.z.c(long, java.util.ArrayList, java.util.ArrayList, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
