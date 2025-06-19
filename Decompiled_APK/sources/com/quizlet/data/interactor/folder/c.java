package com.quizlet.data.interactor.folder;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes2.dex */
public final class c {
    public final com.quizlet.data.repository.folder.i a;
    public final AbstractC5040y b;

    public c(com.quizlet.data.repository.folder.i folderRepository, AbstractC5040y ioDispatcher, int i) {
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(folderRepository, "folderRepository");
                Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
                this.a = folderRepository;
                this.b = ioDispatcher;
                break;
            default:
                Intrinsics.checkNotNullParameter(folderRepository, "repository");
                Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
                this.a = folderRepository;
                this.b = ioDispatcher;
                break;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object a(long r6, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r5 = this;
            boolean r0 = r8 instanceof com.quizlet.data.interactor.folderstudymaterial.i
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.data.interactor.folderstudymaterial.i r0 = (com.quizlet.data.interactor.folderstudymaterial.i) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folderstudymaterial.i r0 = new com.quizlet.data.interactor.folderstudymaterial.i
            r0.<init>(r5, r8)
        L18:
            java.lang.Object r8 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r8)     // Catch: java.lang.Exception -> L48
            goto L43
        L27:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            kotlinx.coroutines.y r8 = r5.b     // Catch: java.lang.Exception -> L48
            com.quizlet.data.interactor.folderstudymaterial.j r2 = new com.quizlet.data.interactor.folderstudymaterial.j     // Catch: java.lang.Exception -> L48
            r4 = 0
            r2.<init>(r5, r6, r4)     // Catch: java.lang.Exception -> L48
            r0.l = r3     // Catch: java.lang.Exception -> L48
            java.lang.Object r8 = kotlinx.coroutines.E.J(r8, r2, r0)     // Catch: java.lang.Exception -> L48
            if (r8 != r1) goto L43
            return r1
        L43:
            com.quizlet.data.model.t1 r8 = (com.quizlet.data.model.C4168t1) r8     // Catch: java.lang.Exception -> L48
            java.util.List r6 = r8.a     // Catch: java.lang.Exception -> L48
            return r6
        L48:
            kotlin.collections.K r6 = kotlin.collections.K.a
            java.lang.String r7 = "studyMaterials"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r7)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.folder.c.a(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object b(long r14, long r16, long r18, boolean r20, kotlin.coroutines.jvm.internal.c r21) {
        /*
            r13 = this;
            r0 = r21
            boolean r2 = r0 instanceof com.quizlet.data.interactor.folder.a
            if (r2 == 0) goto L16
            r2 = r0
            com.quizlet.data.interactor.folder.a r2 = (com.quizlet.data.interactor.folder.a) r2
            int r3 = r2.l
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L16
            int r3 = r3 - r4
            r2.l = r3
        L14:
            r10 = r2
            goto L1c
        L16:
            com.quizlet.data.interactor.folder.a r2 = new com.quizlet.data.interactor.folder.a
            r2.<init>(r13, r0)
            goto L14
        L1c:
            java.lang.Object r0 = r10.j
            kotlin.coroutines.intrinsics.a r11 = kotlin.coroutines.intrinsics.a.a
            int r2 = r10.l
            r12 = 1
            if (r2 == 0) goto L33
            if (r2 != r12) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r0)
            goto L4f
        L2b:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r2)
            throw r0
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            com.quizlet.data.interactor.folder.b r0 = new com.quizlet.data.interactor.folder.b
            r9 = 0
            r1 = r13
            r6 = r14
            r2 = r16
            r4 = r18
            r8 = r20
            r0.<init>(r1, r2, r4, r6, r8, r9)
            r10.l = r12
            kotlinx.coroutines.y r2 = r13.b
            java.lang.Object r0 = kotlinx.coroutines.E.J(r2, r0, r10)
            if (r0 != r11) goto L4f
            return r11
        L4f:
            kotlin.r r0 = (kotlin.r) r0
            java.lang.Object r0 = r0.a
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.folder.c.b(long, long, long, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
