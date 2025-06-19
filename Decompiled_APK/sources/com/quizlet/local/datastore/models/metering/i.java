package com.quizlet.local.datastore.models.metering;

import androidx.datastore.core.InterfaceC1076h;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i {
    public final InterfaceC1076h a;

    public i(InterfaceC1076h dataStore, int i) {
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(dataStore, "dataStore");
                this.a = dataStore;
                break;
            default:
                Intrinsics.checkNotNullParameter(dataStore, "userMeteringInfoDataStore");
                this.a = dataStore;
                break;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object a(long r5, java.lang.Long r7, int r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r4 = this;
            boolean r0 = r9 instanceof com.quizlet.local.datastore.models.metering.f
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.local.datastore.models.metering.f r0 = (com.quizlet.local.datastore.models.metering.f) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.local.datastore.models.metering.f r0 = new com.quizlet.local.datastore.models.metering.f
            r0.<init>(r4, r9)
        L18:
            java.lang.Object r9 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.IllegalArgumentException -> L64
            goto L61
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.lang.StringBuilder r9 = new java.lang.StringBuilder
            r9.<init>()
            r9.append(r5)
            java.lang.String r5 = "_"
            r9.append(r5)
            r9.append(r7)
            r9.append(r5)
            r9.append(r8)
            java.lang.String r5 = r9.toString()
            androidx.datastore.core.h r6 = r4.a     // Catch: java.lang.IllegalArgumentException -> L64
            kotlinx.coroutines.flow.i r6 = r6.getData()     // Catch: java.lang.IllegalArgumentException -> L64
            com.perimeterx.mobile_sdk.local_data.i r7 = new com.perimeterx.mobile_sdk.local_data.i     // Catch: java.lang.IllegalArgumentException -> L64
            r8 = 3
            r7.<init>(r6, r5, r8)     // Catch: java.lang.IllegalArgumentException -> L64
            r0.l = r3     // Catch: java.lang.IllegalArgumentException -> L64
            java.lang.Object r9 = kotlinx.coroutines.flow.e0.r(r7, r0)     // Catch: java.lang.IllegalArgumentException -> L64
            if (r9 != r1) goto L61
            return r1
        L61:
            com.quizlet.local.datastore.models.metering.d r9 = (com.quizlet.local.datastore.models.metering.d) r9     // Catch: java.lang.IllegalArgumentException -> L64
            return r9
        L64:
            r5 = 0
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.local.datastore.models.metering.i.a(long, java.lang.Long, int, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object b(kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.local.datastore.preferences.x0
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.local.datastore.preferences.x0 r0 = (com.quizlet.local.datastore.preferences.x0) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.local.datastore.preferences.x0 r0 = new com.quizlet.local.datastore.preferences.x0
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L48
        L27:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            androidx.datastore.core.h r6 = r5.a
            kotlinx.coroutines.flow.i r6 = r6.getData()
            androidx.compose.material3.internal.H r2 = new androidx.compose.material3.internal.H
            r4 = 8
            r2.<init>(r4, r6, r5)
            r0.l = r3
            java.lang.Object r6 = kotlinx.coroutines.flow.e0.r(r2, r0)
            if (r6 != r1) goto L48
            return r1
        L48:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            if (r6 == 0) goto L50
            boolean r3 = r6.booleanValue()
        L50:
            java.lang.Boolean r6 = java.lang.Boolean.valueOf(r3)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.local.datastore.models.metering.i.b(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object c(com.quizlet.local.datastore.models.metering.d r10, kotlin.coroutines.jvm.internal.c r11) {
        /*
            r9 = this;
            boolean r0 = r11 instanceof com.quizlet.local.datastore.models.metering.g
            if (r0 == 0) goto L13
            r0 = r11
            com.quizlet.local.datastore.models.metering.g r0 = (com.quizlet.local.datastore.models.metering.g) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.local.datastore.models.metering.g r0 = new com.quizlet.local.datastore.models.metering.g
            r0.<init>(r9, r11)
        L18:
            java.lang.Object r11 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            java.lang.String r10 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L75
        L29:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            long r4 = r10.I()
            long r6 = r10.G()
            java.lang.Long r11 = new java.lang.Long
            r11.<init>(r6)
            int r2 = r10.D()
            java.lang.StringBuilder r6 = new java.lang.StringBuilder
            r6.<init>()
            r6.append(r4)
            java.lang.String r4 = "_"
            r6.append(r4)
            r6.append(r11)
            r6.append(r4)
            r6.append(r2)
            java.lang.String r11 = r6.toString()
            com.quizlet.local.datastore.models.metering.h r2 = new com.quizlet.local.datastore.models.metering.h
            r4 = 0
            r2.<init>(r11, r10, r4)
            r0.j = r11
            r0.m = r3
            androidx.datastore.core.h r10 = r9.a
            java.lang.Object r10 = r10.a(r2, r0)
            if (r10 != r1) goto L72
            return r1
        L72:
            r8 = r11
            r11 = r10
            r10 = r8
        L75:
            com.quizlet.local.datastore.models.metering.n r11 = (com.quizlet.local.datastore.models.metering.n) r11
            com.quizlet.local.datastore.models.metering.d r10 = r11.x(r10)
            java.lang.String r11 = "getDataOrThrow(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r10, r11)
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.local.datastore.models.metering.i.c(com.quizlet.local.datastore.models.metering.d, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
