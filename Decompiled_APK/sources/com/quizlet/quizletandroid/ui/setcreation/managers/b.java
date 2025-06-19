package com.quizlet.quizletandroid.ui.setcreation.managers;

import com.quizlet.generated.enums.H;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public static final H b = H.UNITED_STATES;
    public final androidx.work.impl.model.c a;

    public b(androidx.work.impl.model.c userProperties) {
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        this.a = userProperties;
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x00a3  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.jvm.internal.c r12) {
        /*
            r11 = this;
            boolean r0 = r12 instanceof com.quizlet.quizletandroid.ui.setcreation.managers.a
            if (r0 == 0) goto L13
            r0 = r12
            com.quizlet.quizletandroid.ui.setcreation.managers.a r0 = (com.quizlet.quizletandroid.ui.setcreation.managers.a) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.setcreation.managers.a r0 = new com.quizlet.quizletandroid.ui.setcreation.managers.a
            r0.<init>(r11, r12)
        L18:
            java.lang.Object r12 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            java.lang.String r3 = "await(...)"
            r4 = 3
            r5 = 2
            r6 = 1
            if (r2 == 0) goto L4a
            if (r2 == r6) goto L44
            if (r2 == r5) goto L3c
            if (r2 != r4) goto L34
            boolean r1 = r0.l
            boolean r0 = r0.k
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto La6
        L34:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r0)
            throw r12
        L3c:
            boolean r2 = r0.k
            com.quizlet.quizletandroid.ui.setcreation.managers.b r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L88
        L44:
            com.quizlet.quizletandroid.ui.setcreation.managers.b r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L5f
        L4a:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            androidx.work.impl.model.c r12 = r11.a
            io.reactivex.rxjava3.internal.operators.single.g r12 = r12.u()
            r0.j = r11
            r0.o = r6
            java.lang.Object r12 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r12, r0)
            if (r12 != r1) goto L5e
            goto La2
        L5e:
            r2 = r11
        L5f:
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r12, r3)
            java.lang.Boolean r12 = (java.lang.Boolean) r12
            boolean r12 = r12.booleanValue()
            androidx.work.impl.model.c r7 = r2.a
            com.quizlet.local.datastore.preferences.c0 r8 = new com.quizlet.local.datastore.preferences.c0
            r9 = 26
            r8.<init>(r9)
            java.lang.Boolean r9 = java.lang.Boolean.FALSE
            io.reactivex.rxjava3.internal.operators.single.g r7 = r7.o(r8, r9)
            r0.j = r2
            r0.k = r12
            r0.o = r5
            java.lang.Object r5 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r7, r0)
            if (r5 != r1) goto L84
            goto La2
        L84:
            r10 = r2
            r2 = r12
            r12 = r5
            r5 = r10
        L88:
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r12, r3)
            java.lang.Boolean r12 = (java.lang.Boolean) r12
            boolean r12 = r12.booleanValue()
            androidx.work.impl.model.c r3 = r5.a
            r5 = 0
            r0.j = r5
            r0.k = r2
            r0.l = r12
            r0.o = r4
            java.lang.Enum r0 = r3.d(r0)
            if (r0 != r1) goto La3
        La2:
            return r1
        La3:
            r1 = r12
            r12 = r0
            r0 = r2
        La6:
            com.quizlet.generated.enums.H r12 = (com.quizlet.generated.enums.H) r12
            com.quizlet.generated.enums.H r2 = com.quizlet.quizletandroid.ui.setcreation.managers.b.b
            if (r12 == r2) goto Lae
            if (r12 != 0) goto Lb4
        Lae:
            if (r0 == 0) goto Lb4
            if (r1 == 0) goto Lb3
            goto Lb4
        Lb3:
            r6 = 0
        Lb4:
            java.lang.Boolean r12 = java.lang.Boolean.valueOf(r6)
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setcreation.managers.b.a(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
