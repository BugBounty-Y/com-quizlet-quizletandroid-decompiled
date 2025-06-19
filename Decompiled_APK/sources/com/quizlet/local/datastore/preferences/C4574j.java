package com.quizlet.local.datastore.preferences;

import androidx.datastore.core.InterfaceC1076h;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.local.datastore.preferences.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4574j {
    public final InterfaceC1076h a;

    public C4574j(InterfaceC1076h dataStore, int i) {
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(dataStore, "dataStore");
                this.a = dataStore;
                break;
            default:
                Intrinsics.checkNotNullParameter(dataStore, "dataStore");
                this.a = dataStore;
                break;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object a(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.local.datastore.preferences.C4570f
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.local.datastore.preferences.f r0 = (com.quizlet.local.datastore.preferences.C4570f) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.local.datastore.preferences.f r0 = new com.quizlet.local.datastore.preferences.f
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.datastore.preferences.core.f r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L68
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Long r7 = new java.lang.Long
            r7.<init>(r5)
            java.lang.Object[] r5 = new java.lang.Object[]{r7}
            java.lang.Object[] r5 = java.util.Arrays.copyOf(r5, r3)
            java.lang.String r6 = "creator_marketing_last_shown_timestamp_%s"
            java.lang.String r5 = java.lang.String.format(r6, r5)
            java.lang.String r6 = "format(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r6)
            java.lang.String r6 = "name"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r6)
            androidx.datastore.preferences.core.f r6 = new androidx.datastore.preferences.core.f
            r6.<init>(r5)
            androidx.datastore.core.h r5 = r4.a
            kotlinx.coroutines.flow.i r5 = r5.getData()
            r0.j = r6
            r0.m = r3
            java.lang.Object r7 = kotlinx.coroutines.flow.e0.p(r5, r0)
            if (r7 != r1) goto L67
            return r1
        L67:
            r5 = r6
        L68:
            androidx.datastore.preferences.core.b r7 = (androidx.datastore.preferences.core.b) r7
            java.lang.Object r5 = r7.c(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.local.datastore.preferences.C4574j.a(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object b(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.local.datastore.preferences.C4571g
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.local.datastore.preferences.g r0 = (com.quizlet.local.datastore.preferences.C4571g) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.local.datastore.preferences.g r0 = new com.quizlet.local.datastore.preferences.g
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.datastore.preferences.core.f r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L61
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Long r7 = new java.lang.Long
            r7.<init>(r5)
            java.lang.Object[] r5 = new java.lang.Object[]{r7}
            java.lang.Object[] r5 = java.util.Arrays.copyOf(r5, r3)
            java.lang.String r6 = "creator_marketing_user_session_count_%s"
            java.lang.String r5 = java.lang.String.format(r6, r5)
            java.lang.String r6 = "format(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r6)
            androidx.datastore.preferences.core.f r5 = com.google.android.gms.internal.mlkit_vision_barcode.R6.c(r5)
            androidx.datastore.core.h r6 = r4.a
            kotlinx.coroutines.flow.i r6 = r6.getData()
            r0.j = r5
            r0.m = r3
            java.lang.Object r7 = kotlinx.coroutines.flow.e0.p(r6, r0)
            if (r7 != r1) goto L61
            return r1
        L61:
            androidx.datastore.preferences.core.b r7 = (androidx.datastore.preferences.core.b) r7
            java.lang.Object r5 = r7.c(r5)
            java.lang.Integer r5 = (java.lang.Integer) r5
            if (r5 == 0) goto L70
            int r5 = r5.intValue()
            goto L71
        L70:
            r5 = 0
        L71:
            java.lang.Integer r6 = new java.lang.Integer
            r6.<init>(r5)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.local.datastore.preferences.C4574j.b(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
