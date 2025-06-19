package com.quizlet.features.onboarding.ell;

import com.google.android.gms.measurement.internal.J;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ J k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(J j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new q(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((q) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:26:0x0063, code lost:
    
        if (r9 == r0) goto L27;
     */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0050  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x006d  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.j
            r2 = 3
            com.google.android.gms.measurement.internal.J r3 = r8.k
            r4 = 2
            r5 = 1
            if (r1 == 0) goto L25
            if (r1 == r5) goto L21
            if (r1 == r4) goto L1d
            if (r1 != r2) goto L15
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L66
        L15:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L1d:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L48
        L21:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L37
        L25:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.lang.Object r9 = r3.e
            com.lyft.android.scissors.b r9 = (com.lyft.android.scissors.b) r9
            r8.j = r5
            long r6 = r3.b
            java.lang.Object r9 = r9.l(r6, r8)
            if (r9 != r0) goto L37
            goto L65
        L37:
            java.lang.Object r9 = r3.d
            com.quizlet.remote.model.notes.e r9 = (com.quizlet.remote.model.notes.e) r9
            r8.j = r4
            java.lang.Object r1 = r9.e
            java.lang.Enum r1 = (java.lang.Enum) r1
            java.lang.Enum r9 = r9.k(r1)
            if (r9 != r0) goto L48
            goto L65
        L48:
            com.quizlet.featuregate.contracts.enums.c r9 = (com.quizlet.featuregate.contracts.enums.c) r9
            int r9 = r9.ordinal()
            if (r9 == 0) goto L6d
            if (r9 == r5) goto L5b
            if (r9 != r4) goto L55
            goto L5b
        L55:
            kotlin.NoWhenBranchMatchedException r9 = new kotlin.NoWhenBranchMatchedException
            r9.<init>()
            throw r9
        L5b:
            long r4 = r3.b
            r8.j = r2
            java.lang.Object r9 = com.google.android.gms.measurement.internal.J.a(r3, r4, r8)
            if (r9 != r0) goto L66
        L65:
            return r0
        L66:
            java.lang.Boolean r9 = (java.lang.Boolean) r9
            boolean r9 = r9.booleanValue()
            goto L6e
        L6d:
            r9 = 0
        L6e:
            java.lang.Boolean r9 = java.lang.Boolean.valueOf(r9)
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.onboarding.ell.q.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
