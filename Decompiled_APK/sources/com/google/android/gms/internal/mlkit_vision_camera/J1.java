package com.google.android.gms.internal.mlkit_vision_camera;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.CancellationException;
import kotlin.C4937f;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class J1 {
    public static final void a(CoroutineContext coroutineContext, Throwable th) {
        if (th instanceof CancellationException) {
            return;
        }
        try {
            C7.c(th);
        } catch (Throwable th2) {
            C4937f.a(th, th2);
            kotlinx.coroutines.E.u(coroutineContext, th);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object b(androidx.work.impl.model.c r5, com.quizlet.time.b r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            boolean r0 = r7 instanceof com.quizlet.features.onboarding.utils.a
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.features.onboarding.utils.a r0 = (com.quizlet.features.onboarding.utils.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.onboarding.utils.a r0 = new com.quizlet.features.onboarding.utils.a
            r0.<init>(r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L32
            if (r2 != r4) goto L2a
            com.quizlet.time.b r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4f
        L2a:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.local.datastore.preferences.c0 r7 = new com.quizlet.local.datastore.preferences.c0
            r2 = 22
            r7.<init>(r2)
            java.lang.Integer r2 = java.lang.Integer.valueOf(r3)
            io.reactivex.rxjava3.internal.operators.single.g r5 = r5.o(r7, r2)
            r0.j = r6
            r0.l = r4
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r5, r0)
            if (r7 != r1) goto L4f
            return r1
        L4f:
            java.lang.String r5 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r7, r5)
            java.lang.Number r7 = (java.lang.Number) r7
            int r5 = r7.intValue()
            r6.getClass()
            long r6 = com.quizlet.time.b.a()
            long r0 = (long) r5
            long r6 = r6 - r0
            java.util.concurrent.TimeUnit r5 = java.util.concurrent.TimeUnit.DAYS
            r0 = 1
            long r0 = r5.toSeconds(r0)
            int r5 = (r6 > r0 ? 1 : (r6 == r0 ? 0 : -1))
            if (r5 >= 0) goto L70
            r3 = r4
        L70:
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r3)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.J1.b(androidx.work.impl.model.c, com.quizlet.time.b, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final androidx.navigation.K c(Function1 optionsBuilder) {
        Intrinsics.checkNotNullParameter(optionsBuilder, "optionsBuilder");
        androidx.navigation.L l = new androidx.navigation.L();
        optionsBuilder.invoke(l);
        boolean z = l.b;
        androidx.navigation.J j = l.a;
        j.a = z;
        j.b = l.c;
        String str = l.e;
        if (str != null) {
            boolean z2 = l.f;
            boolean z3 = l.g;
            j.d = str;
            j.c = -1;
            j.e = z2;
            j.f = z3;
        } else {
            int i = l.d;
            boolean z4 = l.f;
            boolean z5 = l.g;
            j.c = i;
            j.d = null;
            j.e = z4;
            j.f = z5;
        }
        String str2 = j.d;
        if (str2 == null) {
            return new androidx.navigation.K(j.a, j.b, j.c, j.e, j.f, j.g, j.h);
        }
        boolean z6 = j.a;
        boolean z7 = j.b;
        boolean z8 = j.e;
        boolean z9 = j.f;
        int i2 = j.g;
        int i3 = j.h;
        int i4 = androidx.navigation.B.e;
        androidx.navigation.K k = new androidx.navigation.K(z6, z7, "android-app://androidx.navigation/".concat(str2).hashCode(), z8, z9, i2, i3);
        k.h = str2;
        return k;
    }
}
