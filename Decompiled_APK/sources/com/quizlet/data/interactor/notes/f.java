package com.quizlet.data.interactor.notes;

import com.quizlet.shared.usecase.studynotes.t;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f {
    public final t a;
    public final com.quizlet.data.interactor.set.c b;

    public f(t getStudyNotesForUserUseCase, com.quizlet.data.interactor.set.c getUserUseCase) {
        Intrinsics.checkNotNullParameter(getStudyNotesForUserUseCase, "getStudyNotesForUserUseCase");
        Intrinsics.checkNotNullParameter(getUserUseCase, "getUserUseCase");
        this.a = getStudyNotesForUserUseCase;
        this.b = getUserUseCase;
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x00aa A[LOOP:0: B:35:0x00a4->B:37:0x00aa, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable a(int r6, int r7, boolean r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r5 = this;
            boolean r0 = r9 instanceof com.quizlet.data.interactor.notes.e
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.data.interactor.notes.e r0 = (com.quizlet.data.interactor.notes.e) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.interactor.notes.e r0 = new com.quizlet.data.interactor.notes.e
            r0.<init>(r5, r9)
        L18:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L41
            if (r2 == r4) goto L36
            if (r2 != r3) goto L2e
            java.lang.Object r6 = r0.j
            java.util.List r6 = (java.util.List) r6
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L8e
        L2e:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L36:
            java.lang.Object r6 = r0.j
            com.quizlet.data.interactor.notes.f r6 = (com.quizlet.data.interactor.notes.f) r6
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Exception -> L3e
            goto L54
        L3e:
            r6 = move-exception
            goto Lba
        L41:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.quizlet.shared.usecase.studynotes.t r9 = r5.a     // Catch: java.lang.Exception -> L3e
            r0.j = r5     // Catch: java.lang.Exception -> L3e
            r0.m = r4     // Catch: java.lang.Exception -> L3e
            com.quizlet.shared.usecase.studynotes.l r9 = (com.quizlet.shared.usecase.studynotes.l) r9     // Catch: java.lang.Exception -> L3e
            java.lang.Object r9 = r9.a(r6, r7, r8, r0)     // Catch: java.lang.Exception -> L3e
            if (r9 != r1) goto L53
            goto L8c
        L53:
            r6 = r5
        L54:
            r7 = r9
            java.util.List r7 = (java.util.List) r7     // Catch: java.lang.Exception -> L3e
            boolean r8 = r7.isEmpty()
            if (r8 == 0) goto L60
            kotlin.collections.K r6 = kotlin.collections.K.a
            return r6
        L60:
            com.quizlet.data.interactor.set.c r6 = r6.b
            java.lang.Object r8 = kotlin.collections.CollectionsKt.L(r7)
            com.quizlet.shared.models.notes.FullStudyNotesInfo r8 = (com.quizlet.shared.models.notes.FullStudyNotesInfo) r8
            long r8 = r8.c
            java.lang.Object r2 = r6.a
            com.quizlet.data.repository.user.e r2 = (com.quizlet.data.repository.user.e) r2
            io.reactivex.rxjava3.internal.operators.observable.r r8 = r2.e(r8)
            kotlinx.coroutines.flow.c r8 = com.google.android.gms.internal.mlkit_vision_camera.K1.f(r8)
            java.lang.Object r6 = r6.c
            kotlinx.coroutines.y r6 = (kotlinx.coroutines.AbstractC5040y) r6
            kotlinx.coroutines.flow.i r6 = kotlinx.coroutines.flow.e0.s(r8, r6)
            com.jakewharton.rxbinding4.a r6 = com.google.android.gms.internal.mlkit_vision_camera.K1.g(r6)
            r0.j = r7
            r0.m = r3
            java.lang.Object r9 = com.google.android.gms.internal.mlkit_vision_camera.I1.c(r6, r0)
            if (r9 != r1) goto L8d
        L8c:
            return r1
        L8d:
            r6 = r7
        L8e:
            java.lang.String r7 = "awaitFirst(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r9, r7)
            com.quizlet.data.model.User r9 = (com.quizlet.data.model.User) r9
            java.util.ArrayList r7 = new java.util.ArrayList
            r8 = 10
            int r8 = kotlin.collections.C.q(r6, r8)
            r7.<init>(r8)
            java.util.Iterator r6 = r6.iterator()
        La4:
            boolean r8 = r6.hasNext()
            if (r8 == 0) goto Lb9
            java.lang.Object r8 = r6.next()
            com.quizlet.shared.models.notes.FullStudyNotesInfo r8 = (com.quizlet.shared.models.notes.FullStudyNotesInfo) r8
            r0 = 0
            com.quizlet.data.model.NotesToValueInfo r8 = com.google.android.gms.internal.mlkit_vision_document_scanner.D6.m(r8, r9, r0)
            r7.add(r8)
            goto La4
        Lb9:
            return r7
        Lba:
            com.quizlet.data.exceptions.library.LibraryNotesException r7 = new com.quizlet.data.exceptions.library.LibraryNotesException
            r7.<init>(r6)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.notes.f.a(int, int, boolean, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }
}
