package com.quizlet.data.interactor.metering;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e {
    public final com.quizlet.data.repository.folderwithcreator.e a;
    public final com.quizlet.data.repository.folderset.c b;

    public e(com.quizlet.data.repository.folderwithcreator.e remoteRepository, com.quizlet.data.repository.folderset.c localRepository) {
        Intrinsics.checkNotNullParameter(remoteRepository, "remoteRepository");
        Intrinsics.checkNotNullParameter(localRepository, "localRepository");
        this.a = remoteRepository;
        this.b = localRepository;
    }

    /* JADX WARN: Code restructure failed: missing block: B:22:0x005b, code lost:
    
        if (r9.s((com.quizlet.data.model.InterfaceC4176w0) r13, r6) == r0) goto L23;
     */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(long r9, java.lang.Long r11, com.quizlet.generated.enums.P r12, kotlin.coroutines.jvm.internal.c r13) {
        /*
            r8 = this;
            boolean r0 = r13 instanceof com.quizlet.data.interactor.metering.d
            if (r0 == 0) goto L14
            r0 = r13
            com.quizlet.data.interactor.metering.d r0 = (com.quizlet.data.interactor.metering.d) r0
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
            com.quizlet.data.interactor.metering.d r0 = new com.quizlet.data.interactor.metering.d
            r0.<init>(r8, r13)
            goto L12
        L1a:
            java.lang.Object r13 = r6.k
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.m
            r7 = 2
            r2 = 1
            if (r1 == 0) goto L3a
            if (r1 == r2) goto L34
            if (r1 != r7) goto L2c
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L5e
        L2c:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L34:
            com.quizlet.data.interactor.metering.e r9 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L4e
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            r6.j = r8
            r6.m = r2
            com.quizlet.data.repository.folderset.c r1 = r8.b
            r2 = r9
            r4 = r11
            r5 = r12
            java.lang.Object r13 = r1.a(r2, r4, r5, r6)
            if (r13 != r0) goto L4d
            goto L5d
        L4d:
            r9 = r8
        L4e:
            com.quizlet.data.model.w0 r13 = (com.quizlet.data.model.InterfaceC4176w0) r13
            com.quizlet.data.repository.folderwithcreator.e r9 = r9.a
            r10 = 0
            r6.j = r10
            r6.m = r7
            java.lang.Object r9 = r9.s(r13, r6)
            if (r9 != r0) goto L5e
        L5d:
            return r0
        L5e:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.metering.e.a(long, java.lang.Long, com.quizlet.generated.enums.P, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
