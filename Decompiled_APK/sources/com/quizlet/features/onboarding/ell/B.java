package com.quizlet.features.onboarding.ell;

import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.google.android.gms.measurement.internal.J;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class B extends w0 {
    public final J b;
    public final n c;
    public final d0 d;
    public final s0 e;
    public v f;

    public B(J onboardingELLPresentationUseCase, n onboardingELLLogger) {
        Intrinsics.checkNotNullParameter(onboardingELLPresentationUseCase, "onboardingELLPresentationUseCase");
        Intrinsics.checkNotNullParameter(onboardingELLLogger, "onboardingELLLogger");
        this.b = onboardingELLPresentationUseCase;
        this.c = onboardingELLLogger;
        this.d = e0.b(0, 0, null, 7);
        this.e = e0.c(w.a);
        this.f = new v(kotlinx.collections.immutable.implementations.immutableList.g.c);
        E.A(p0.j(this), null, null, new y(this, null), 3);
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x006d, code lost:
    
        if (r6.emit(r8, r0) == r1) goto L24;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.features.onboarding.ell.B r6, boolean r7, com.quizlet.features.onboarding.ell.u r8, kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            r6.getClass()
            boolean r0 = r9 instanceof com.quizlet.features.onboarding.ell.z
            if (r0 == 0) goto L16
            r0 = r9
            com.quizlet.features.onboarding.ell.z r0 = (com.quizlet.features.onboarding.ell.z) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.n = r1
            goto L1b
        L16:
            com.quizlet.features.onboarding.ell.z r0 = new com.quizlet.features.onboarding.ell.z
            r0.<init>(r6, r9)
        L1b:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            r5 = 0
            if (r2 == 0) goto L3e
            if (r2 == r4) goto L36
            if (r2 != r3) goto L2e
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L70
        L2e:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L36:
            com.quizlet.features.onboarding.ell.u r8 = r0.k
            com.quizlet.features.onboarding.ell.B r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L61
        L3e:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r0.j = r6
            r0.k = r8
            r0.n = r4
            com.google.android.gms.measurement.internal.J r9 = r6.b
            r9.getClass()
            com.quizlet.features.onboarding.ell.p r2 = new com.quizlet.features.onboarding.ell.p
            r2.<init>(r7, r9, r5)
            java.lang.Object r7 = r9.c
            kotlinx.coroutines.y r7 = (kotlinx.coroutines.AbstractC5040y) r7
            java.lang.Object r7 = kotlinx.coroutines.E.J(r7, r2, r0)
            if (r7 != r1) goto L5c
            goto L5e
        L5c:
            kotlin.Unit r7 = kotlin.Unit.a
        L5e:
            if (r7 != r1) goto L61
            goto L6f
        L61:
            kotlinx.coroutines.flow.d0 r6 = r6.d
            r0.j = r5
            r0.k = r5
            r0.n = r3
            java.lang.Object r6 = r6.emit(r8, r0)
            if (r6 != r1) goto L70
        L6f:
            return r1
        L70:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.onboarding.ell.B.A(com.quizlet.features.onboarding.ell.B, boolean, com.quizlet.features.onboarding.ell.u, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
