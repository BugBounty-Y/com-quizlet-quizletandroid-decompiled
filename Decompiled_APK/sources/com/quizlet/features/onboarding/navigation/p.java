package com.quizlet.features.onboarding.navigation;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.android.billingclient.api.C1472a;
import kotlin.Metadata;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.D;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.Q;
import kotlinx.coroutines.flow.Y;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.h0;

@Metadata
/* loaded from: classes3.dex */
public final class p extends w0 {
    public final m0 b;
    public final com.quizlet.data.repository.progress.b c;
    public final d0 d;
    public final Y e;

    public p(m0 savedStateHandle, com.quizlet.data.repository.progress.b navigationStepEligibilityUseCase) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(navigationStepEligibilityUseCase, "navigationStepEligibilityUseCase");
        this.b = savedStateHandle;
        this.c = navigationStepEligibilityUseCase;
        d0 d0VarB = e0.b(1, 0, null, 6);
        this.d = d0VarB;
        androidx.lifecycle.viewmodel.internal.a aVarJ = p0.j(this);
        kotlinx.coroutines.flow.p0 p0VarA = h0.a(2);
        com.google.android.gms.cloudmessaging.k kVarJ = e0.j(d0VarB, 0);
        d0 d0VarA = e0.a(0, kVarJ.b, (kotlinx.coroutines.channels.a) kVarJ.d);
        C1472a c1472a = e0.a;
        InterfaceC4992i interfaceC4992i = (InterfaceC4992i) kVarJ.c;
        E.z(aVarJ, (CoroutineContext) kVarJ.e, p0VarA.equals(h0.a) ? D.a : D.d, new Q(p0VarA, interfaceC4992i, d0VarA, c1472a, null));
        this.e = new Y(d0VarA);
        E.A(p0.j(this), null, null, new m(this, null), 3);
    }

    public static void B(p pVar, l step, Integer num, int i) {
        if ((i & 4) != 0) {
            num = null;
        }
        pVar.getClass();
        Intrinsics.checkNotNullParameter(step, "step");
        E.A(p0.j(pVar), null, null, new o(pVar, num, step, null), 3);
    }

    /* JADX WARN: Code restructure failed: missing block: B:53:0x00df, code lost:
    
        if (r10.emit(r9, r0) == r1) goto L61;
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x0101, code lost:
    
        if (r2.A(r9, r0) == r1) goto L61;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object A(com.quizlet.features.onboarding.navigation.l r9, kotlin.coroutines.jvm.internal.c r10) {
        /*
            Method dump skipped, instructions count: 271
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.onboarding.navigation.p.A(com.quizlet.features.onboarding.navigation.l, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
