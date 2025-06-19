package com.quizlet.featuregate.features.folder;

import com.quizlet.billing.subscriptions.i;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.wrappers.LoggedInUserStatus;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes2.dex */
public final class b implements h {
    public final androidx.work.impl.model.c a;

    public b(androidx.work.impl.model.c userProperties, int i) {
        switch (i) {
            case 2:
                this.a = userProperties;
                break;
            default:
                Intrinsics.checkNotNullParameter(userProperties, "userProperties");
                this.a = userProperties;
                break;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x0064, code lost:
    
        if (r6 == r1) goto L24;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object a(kotlin.coroutines.h r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.featuregate.features.folder.a
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.featuregate.features.folder.a r0 = (com.quizlet.featuregate.features.folder.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.featuregate.features.folder.a r0 = new com.quizlet.featuregate.features.folder.a
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L67
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L32:
            com.quizlet.featuregate.features.folder.b r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4d
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            androidx.work.impl.model.c r6 = r5.a
            io.reactivex.rxjava3.internal.operators.single.g r6 = r6.r()
            r0.j = r5
            r0.m = r4
            java.lang.Object r6 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r6, r0)
            if (r6 != r1) goto L4c
            goto L66
        L4c:
            r2 = r5
        L4d:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 != 0) goto L70
            androidx.work.impl.model.c r6 = r2.a
            io.reactivex.rxjava3.internal.operators.single.g r6 = r6.u()
            r2 = 0
            r0.j = r2
            r0.m = r3
            java.lang.Object r6 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r6, r0)
            if (r6 != r1) goto L67
        L66:
            return r1
        L67:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 != 0) goto L70
            goto L71
        L70:
            r4 = 0
        L71:
            java.lang.Boolean r6 = java.lang.Boolean.valueOf(r4)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.featuregate.features.folder.b.a(kotlin.coroutines.h):java.lang.Object");
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        LoggedInUserStatus status = (LoggedInUserStatus) obj;
        Intrinsics.checkNotNullParameter(status, "status");
        DBUser currentUser = status.getCurrentUser();
        if (!status.isLoggedIn() || currentUser == null) {
            return p.f(Boolean.FALSE);
        }
        return ((i) this.a.b).b(new com.quizlet.billing.model.b(currentUser.getSelfIdentifiedUserType(), currentUser.getUserUpgradeType(), 16, currentUser.getId(), currentUser.getObfuscatedUserId()));
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Enum b(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.features.subjects.usecase.c
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.features.subjects.usecase.c r0 = (com.quizlet.features.subjects.usecase.c) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.subjects.usecase.c r0 = new com.quizlet.features.subjects.usecase.c
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L3d
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.l = r3
            androidx.work.impl.model.c r5 = r4.a
            java.lang.Enum r5 = r5.d(r0)
            if (r5 != r1) goto L3d
            return r1
        L3d:
            com.quizlet.generated.enums.H r5 = (com.quizlet.generated.enums.H) r5
            if (r5 != 0) goto L43
            r5 = -1
            goto L4b
        L43:
            int[] r0 = com.quizlet.features.subjects.model.d.a
            int r5 = r5.ordinal()
            r5 = r0[r5]
        L4b:
            if (r5 == r3) goto L62
            r0 = 2
            if (r5 == r0) goto L5f
            r0 = 3
            if (r5 == r0) goto L5c
            r0 = 4
            if (r5 == r0) goto L59
            com.quizlet.features.subjects.model.c r5 = com.quizlet.features.subjects.model.c.e
            return r5
        L59:
            com.quizlet.features.subjects.model.c r5 = com.quizlet.features.subjects.model.c.d
            return r5
        L5c:
            com.quizlet.features.subjects.model.c r5 = com.quizlet.features.subjects.model.c.c
            return r5
        L5f:
            com.quizlet.features.subjects.model.c r5 = com.quizlet.features.subjects.model.c.b
            return r5
        L62:
            com.quizlet.features.subjects.model.c r5 = com.quizlet.features.subjects.model.c.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.featuregate.features.folder.b.b(kotlin.coroutines.jvm.internal.c):java.lang.Enum");
    }

    public b(androidx.work.impl.model.c userProperties, AbstractC5040y dispatcher) {
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.a = userProperties;
    }
}
