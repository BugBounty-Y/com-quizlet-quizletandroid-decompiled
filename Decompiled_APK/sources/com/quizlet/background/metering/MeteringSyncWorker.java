package com.quizlet.background.metering;

import android.content.Context;
import androidx.work.CoroutineWorker;
import androidx.work.WorkerParameters;
import com.quizlet.data.interactor.metering.e;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class MeteringSyncWorker extends CoroutineWorker {
    public final WorkerParameters g;
    public final e h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public MeteringSyncWorker(@NotNull Context context, @NotNull WorkerParameters workerParams, @NotNull e syncMeteringUseCase) {
        super(context, workerParams);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(workerParams, "workerParams");
        Intrinsics.checkNotNullParameter(syncMeteringUseCase, "syncMeteringUseCase");
        this.g = workerParams;
        this.h = syncMeteringUseCase;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    @Override // androidx.work.CoroutineWorker
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.h r12) {
        /*
            r11 = this;
            boolean r0 = r12 instanceof com.quizlet.background.metering.a
            if (r0 == 0) goto L14
            r0 = r12
            com.quizlet.background.metering.a r0 = (com.quizlet.background.metering.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.l = r1
        L12:
            r6 = r0
            goto L1c
        L14:
            com.quizlet.background.metering.a r0 = new com.quizlet.background.metering.a
            kotlin.coroutines.jvm.internal.c r12 = (kotlin.coroutines.jvm.internal.c) r12
            r0.<init>(r11, r12)
            goto L12
        L1c:
            java.lang.Object r12 = r6.j
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.l
            r2 = 1
            if (r1 == 0) goto L38
            if (r1 != r2) goto L30
            androidx.glance.appwidget.protobuf.Z.e(r12)     // Catch: java.lang.Exception -> L2c
            goto La2
        L2c:
            r0 = move-exception
            r12 = r0
            goto La7
        L30:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r0)
            throw r12
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            androidx.work.WorkerParameters r12 = r11.g
            androidx.work.k r1 = r12.b
            java.lang.String r3 = "userId"
            long r3 = r1.b(r3)
            androidx.work.k r1 = r12.b
            java.lang.String r5 = "resourceId"
            long r7 = r1.b(r5)
            androidx.work.k r12 = r12.b
            r12.getClass()
            java.lang.String r1 = "eventType"
            java.lang.String r5 = "key"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r5)
            r5 = -1
            java.lang.Integer r5 = java.lang.Integer.valueOf(r5)
            java.util.HashMap r12 = r12.a
            java.lang.Object r12 = r12.get(r1)
            boolean r1 = r12 instanceof java.lang.Integer
            if (r1 == 0) goto L69
            r5 = r12
        L69:
            java.lang.Number r5 = (java.lang.Number) r5
            int r12 = r5.intValue()
            java.lang.String r1 = "failure(...)"
            if (r12 >= 0) goto L7c
            androidx.work.u r12 = new androidx.work.u
            r12.<init>()
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r12, r1)
            return r12
        L7c:
            com.quizlet.generated.enums.O r5 = com.quizlet.generated.enums.P.Companion
            r5.getClass()
            com.quizlet.generated.enums.P r5 = com.quizlet.generated.enums.O.a(r12)
            r9 = 0
            int r12 = (r3 > r9 ? 1 : (r3 == r9 ? 0 : -1))
            if (r12 < 0) goto Lbc
            int r12 = (r7 > r9 ? 1 : (r7 == r9 ? 0 : -1))
            if (r12 >= 0) goto L90
            goto Lbc
        L90:
            com.quizlet.data.interactor.metering.e r1 = r11.h     // Catch: java.lang.Exception -> L2c
            r12 = r2
            r2 = r3
            java.lang.Long r4 = new java.lang.Long     // Catch: java.lang.Exception -> L2c
            r4.<init>(r7)     // Catch: java.lang.Exception -> L2c
            r6.l = r12     // Catch: java.lang.Exception -> L2c
            java.lang.Object r12 = r1.a(r2, r4, r5, r6)     // Catch: java.lang.Exception -> L2c
            if (r12 != r0) goto La2
            return r0
        La2:
            androidx.work.w r12 = androidx.work.x.a()     // Catch: java.lang.Exception -> L2c
            return r12
        La7:
            boolean r0 = r12 instanceof java.net.UnknownHostException
            if (r0 != 0) goto Lb6
            boolean r12 = r12 instanceof java.net.SocketTimeoutException
            if (r12 == 0) goto Lb0
            goto Lb6
        Lb0:
            androidx.work.u r12 = new androidx.work.u
            r12.<init>()
            goto Lbb
        Lb6:
            androidx.work.v r12 = new androidx.work.v
            r12.<init>()
        Lbb:
            return r12
        Lbc:
            androidx.work.u r12 = new androidx.work.u
            r12.<init>()
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r12, r1)
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.background.metering.MeteringSyncWorker.a(kotlin.coroutines.h):java.lang.Object");
    }
}
