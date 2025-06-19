package com.quizlet.features.practicetest.takingtest.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ l k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(l lVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:27:0x0084, code lost:
    
        if (com.quizlet.features.practicetest.takingtest.viewmodel.l.A(r6, r9) == r0) goto L28;
     */
    /* JADX WARN: Removed duplicated region for block: B:26:0x007e  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0087  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) throws java.lang.Throwable {
        /*
            r9 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r9.j
            r2 = 0
            r3 = 1
            r4 = 3
            r5 = 2
            com.quizlet.features.practicetest.takingtest.viewmodel.l r6 = r9.k
            if (r1 == 0) goto L27
            if (r1 == r3) goto L23
            if (r1 == r5) goto L1f
            if (r1 != r4) goto L17
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L98
        L17:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L1f:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L6d
        L23:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L3b
        L27:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            kotlinx.coroutines.flow.s0 r10 = r6.k
            com.quizlet.features.practicetest.takingtest.data.H r1 = com.quizlet.features.practicetest.takingtest.data.H.a
            r9.j = r3
            r10.getClass()
            r10.m(r2, r1)
            kotlin.Unit r10 = kotlin.Unit.a
            if (r10 != r0) goto L3b
            goto L86
        L3b:
            com.quizlet.features.practicetest.takingtest.usecase.f r10 = r6.c
            java.lang.String r1 = r6.B()
            java.lang.String r7 = r6.C()
            r9.j = r5
            r10.getClass()
            int[] r5 = com.quizlet.features.practicetest.takingtest.usecase.a.a
            com.quizlet.data.model.U0 r8 = r6.i
            int r8 = r8.ordinal()
            r5 = r5[r8]
            if (r5 != r3) goto L5b
            java.lang.Object r10 = r10.c(r7, r9)
            goto L6a
        L5b:
            int r3 = r1.length()
            if (r3 != 0) goto L66
            java.lang.Object r10 = r10.c(r7, r9)
            goto L6a
        L66:
            java.lang.Object r10 = r10.b(r1, r9)
        L6a:
            if (r10 != r0) goto L6d
            goto L86
        L6d:
            com.quizlet.features.practicetest.takingtest.data.L r10 = (com.quizlet.features.practicetest.takingtest.data.L) r10
            androidx.lifecycle.m0 r1 = r6.b
            java.lang.String r3 = r10.a
            java.lang.String r5 = "questionBankUuid"
            r1.c(r3, r5)
            com.quizlet.features.practicetest.takingtest.data.J r10 = r10.b
            boolean r1 = r10 instanceof com.quizlet.features.practicetest.takingtest.data.I
            if (r1 == 0) goto L87
            r9.j = r4
            java.lang.Object r10 = com.quizlet.features.practicetest.takingtest.viewmodel.l.A(r6, r9)
            if (r10 != r0) goto L98
        L86:
            return r0
        L87:
            com.quizlet.features.practicetest.takingtest.data.F r10 = (com.quizlet.features.practicetest.takingtest.data.F) r10
            com.quizlet.features.practicetest.takingtest.data.N r0 = r10.e
            if (r0 == 0) goto L90
            r6.D(r0)
        L90:
            kotlinx.coroutines.flow.s0 r0 = r6.k
            r0.getClass()
            r0.m(r2, r10)
        L98:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.practicetest.takingtest.viewmodel.i.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
