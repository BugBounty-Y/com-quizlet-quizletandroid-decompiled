package com.quizlet.data.interactor.metering;

import com.quizlet.data.repository.metering.j;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b {
    public final j a;
    public final org.slf4j.b b;

    public b(j repository, org.slf4j.b logger) {
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.a = repository;
        this.b = logger;
    }

    /* JADX WARN: Removed duplicated region for block: B:35:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0080  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable a(long r7, java.lang.Long r9, com.quizlet.generated.enums.P r10, boolean r11, kotlin.coroutines.jvm.internal.c r12) {
        /*
            r6 = this;
            boolean r0 = r12 instanceof com.quizlet.data.interactor.metering.a
            if (r0 == 0) goto L14
            r0 = r12
            com.quizlet.data.interactor.metering.a r0 = (com.quizlet.data.interactor.metering.a) r0
            int r1 = r0.p
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.p = r1
        L12:
            r12 = r0
            goto L1a
        L14:
            com.quizlet.data.interactor.metering.a r0 = new com.quizlet.data.interactor.metering.a
            r0.<init>(r6, r12)
            goto L12
        L1a:
            java.lang.Object r0 = r12.n
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r12.p
            r3 = 1
            if (r2 == 0) goto L3f
            if (r2 != r3) goto L37
            long r7 = r12.m
            com.quizlet.generated.enums.P r10 = r12.l
            java.lang.Long r9 = r12.k
            com.quizlet.data.interactor.metering.b r11 = r12.j
            androidx.glance.appwidget.protobuf.Z.e(r0)     // Catch: java.lang.Exception -> L31
            goto L69
        L31:
            r0 = move-exception
            r12 = r0
            r3 = r7
            r2 = r9
            r1 = r10
            goto L74
        L37:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L3f:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            if (r11 != 0) goto L4f
            com.quizlet.data.model.o2 r0 = new com.quizlet.data.model.o2
            com.quizlet.generated.enums.S r5 = com.quizlet.generated.enums.S.NOT_ENROLLED_IN_EXPERIMENT
            r3 = r7
            r2 = r9
            r1 = r10
            r0.<init>(r1, r2, r3, r5)
            return r0
        L4f:
            r11 = r10
            r10 = r9
            r8 = r7
            com.quizlet.data.repository.metering.j r7 = r6.a     // Catch: java.lang.Exception -> L71
            r12.j = r6     // Catch: java.lang.Exception -> L71
            r12.k = r10     // Catch: java.lang.Exception -> L71
            r12.l = r11     // Catch: java.lang.Exception -> L71
            r12.m = r8     // Catch: java.lang.Exception -> L71
            r12.p = r3     // Catch: java.lang.Exception -> L71
            java.lang.Object r0 = r7.a(r8, r10, r11, r12)     // Catch: java.lang.Exception -> L71
            if (r0 != r1) goto L65
            return r1
        L65:
            r7 = r8
            r9 = r10
            r10 = r11
            r11 = r6
        L69:
            com.quizlet.data.model.w0 r0 = (com.quizlet.data.model.InterfaceC4176w0) r0     // Catch: java.lang.Exception -> L31
            return r0
        L6c:
            r3 = r8
            r2 = r10
            r1 = r11
            r11 = r6
            goto L74
        L71:
            r0 = move-exception
            r12 = r0
            goto L6c
        L74:
            boolean r7 = r12 instanceof com.quizlet.data.repository.metering.MeteringInfoCombinedRepository$MeteringInfoNotFound
            java.lang.String r8 = "Exception in the GetMeteringInfoUseCase while getting the metering info"
            if (r7 == 0) goto L80
            org.slf4j.b r7 = r11.b
            r7.h(r8, r12)
            goto L85
        L80:
            org.slf4j.b r7 = r11.b
            r7.c(r8, r12)
        L85:
            com.quizlet.data.model.o2 r0 = new com.quizlet.data.model.o2
            com.quizlet.generated.enums.S r5 = com.quizlet.generated.enums.S.CONTROL_VARIANT
            r0.<init>(r1, r2, r3, r5)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.metering.b.a(long, java.lang.Long, com.quizlet.generated.enums.P, boolean, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }
}
