package com.quizlet.features.practicetest.takingtest.viewmodel;

import com.quizlet.features.practicetest.takingtest.data.F;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ Throwable k;
    public final /* synthetic */ l l;
    public final /* synthetic */ F m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(Throwable th, l lVar, F f, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = th;
        this.l = lVar;
        this.m = f;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0035, code lost:
    
        if (r7.emit(r1, r6) == r0) goto L21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x005d, code lost:
    
        if (r7.emit(r1, r6) == r0) goto L21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x005f, code lost:
    
        return r0;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r7) {
        /*
            r6 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.j
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L19
            if (r1 == r3) goto L15
            if (r1 != r2) goto Ld
            goto L15
        Ld:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L15:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L60
        L19:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Throwable r7 = r6.k
            boolean r7 = r7 instanceof com.quizlet.data.exceptions.practicetests.PracticeTestPaywallException
            com.quizlet.features.practicetest.takingtest.viewmodel.l r1 = r6.l
            if (r7 == 0) goto L38
            kotlinx.coroutines.flow.d0 r7 = r1.m
            com.quizlet.features.practicetest.takingtest.data.B r1 = new com.quizlet.features.practicetest.takingtest.data.B
            retrofit2.adapter.rxjava3.d r2 = com.quizlet.features.infra.models.upgrade.a.b
            java.lang.String r2 = "grade_practice_test"
            r1.<init>(r2)
            r6.j = r3
            java.lang.Object r7 = r7.emit(r1, r6)
            if (r7 != r0) goto L60
            goto L5f
        L38:
            com.quizlet.features.practicetest.takingtest.data.F r7 = r6.m
            if (r7 == 0) goto L50
        L3c:
            kotlinx.coroutines.flow.s0 r3 = r1.k
            java.lang.Object r4 = r3.getValue()
            r5 = r4
            com.quizlet.features.practicetest.takingtest.data.J r5 = (com.quizlet.features.practicetest.takingtest.data.J) r5
            r5 = 0
            com.quizlet.features.practicetest.takingtest.data.F r5 = com.quizlet.features.practicetest.takingtest.data.F.a(r7, r5)
            boolean r3 = r3.k(r4, r5)
            if (r3 == 0) goto L3c
        L50:
            kotlinx.coroutines.flow.d0 r7 = r1.l
            com.quizlet.features.practicetest.takingtest.data.j r1 = new com.quizlet.features.practicetest.takingtest.data.j
            r1.<init>()
            r6.j = r2
            java.lang.Object r7 = r7.emit(r1, r6)
            if (r7 != r0) goto L60
        L5f:
            return r0
        L60:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.practicetest.takingtest.viewmodel.e.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
