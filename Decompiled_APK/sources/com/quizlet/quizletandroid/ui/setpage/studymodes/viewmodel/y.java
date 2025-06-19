package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import com.quizlet.eventlogger.features.metering.StudyModeMeteringEventLogger;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.I;

/* loaded from: classes3.dex */
public final class y {
    public final long a;
    public final androidx.work.impl.model.c b;
    public final com.quizlet.data.interactor.metering.b c;
    public final StudyModeMeteringEventLogger d;
    public final AbstractC5040y e;
    public I f;
    public I g;

    public y(long j, androidx.work.impl.model.c userProperties, com.quizlet.data.interactor.metering.b getMeteringInfoUseCase, StudyModeMeteringEventLogger meteringLogger, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(getMeteringInfoUseCase, "getMeteringInfoUseCase");
        Intrinsics.checkNotNullParameter(meteringLogger, "meteringLogger");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = j;
        this.b = userProperties;
        this.c = getMeteringInfoUseCase;
        this.d = meteringLogger;
        this.e = ioDispatcher;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0017  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.y r8, long r9, com.quizlet.generated.enums.P r11, kotlin.coroutines.jvm.internal.c r12) {
        /*
            r8.getClass()
            boolean r0 = r12 instanceof com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.v
            if (r0 == 0) goto L17
            r0 = r12
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.v r0 = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.v) r0
            int r1 = r0.p
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L17
            int r1 = r1 - r2
            r0.p = r1
        L15:
            r7 = r0
            goto L1d
        L17:
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.v r0 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.v
            r0.<init>(r8, r12)
            goto L15
        L1d:
            java.lang.Object r12 = r7.n
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.p
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L45
            if (r1 == r3) goto L37
            if (r1 != r2) goto L2f
            androidx.glance.appwidget.protobuf.Z.e(r12)
            return r12
        L2f:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L37:
            long r8 = r7.m
            com.quizlet.generated.enums.P r11 = r7.l
            java.lang.Long r10 = r7.k
            com.quizlet.data.interactor.metering.b r1 = r7.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            r4 = r10
        L43:
            r5 = r11
            goto L68
        L45:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            java.lang.Long r12 = new java.lang.Long
            r12.<init>(r9)
            com.quizlet.data.interactor.metering.b r1 = r8.c
            r7.j = r1
            r7.k = r12
            r7.l = r11
            long r9 = r8.a
            r7.m = r9
            r7.p = r3
            androidx.work.impl.model.c r8 = r8.b
            java.lang.Object r8 = androidx.camera.core.AbstractC0151c.a(r8, r7)
            if (r8 != r0) goto L64
            goto L7e
        L64:
            r4 = r12
            r12 = r8
            r8 = r9
            goto L43
        L68:
            java.lang.Boolean r12 = (java.lang.Boolean) r12
            boolean r6 = r12.booleanValue()
            r10 = 0
            r7.j = r10
            r7.k = r10
            r7.l = r10
            r7.p = r2
            r2 = r8
            java.io.Serializable r8 = r1.a(r2, r4, r5, r6, r7)
            if (r8 != r0) goto L7f
        L7e:
            return r0
        L7f:
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.y.a(com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.y, long, com.quizlet.generated.enums.P, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
