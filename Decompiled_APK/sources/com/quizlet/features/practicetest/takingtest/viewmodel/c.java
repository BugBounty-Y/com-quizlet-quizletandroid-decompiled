package com.quizlet.features.practicetest.takingtest.viewmodel;

import com.quizlet.features.practicetest.takingtest.data.F;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ F k;
    public final /* synthetic */ l l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(F f, l lVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = f;
        this.l = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x005e, code lost:
    
        if (r1.emit(r3, r7) == r0) goto L19;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) throws java.lang.Throwable {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.j
            com.quizlet.features.practicetest.takingtest.viewmodel.l r2 = r7.l
            r3 = 1
            r4 = 2
            if (r1 == 0) goto L1e
            if (r1 == r3) goto L1a
            if (r1 != r4) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L61
        L12:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L4d
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.features.practicetest.takingtest.data.F r8 = r7.k
            if (r8 == 0) goto L38
        L25:
            kotlinx.coroutines.flow.s0 r1 = r2.k
            java.lang.Object r5 = r1.getValue()
            r6 = r5
            com.quizlet.features.practicetest.takingtest.data.J r6 = (com.quizlet.features.practicetest.takingtest.data.J) r6
            com.quizlet.features.practicetest.takingtest.data.F r6 = com.quizlet.features.practicetest.takingtest.data.F.a(r8, r3)
            boolean r1 = r1.k(r5, r6)
            if (r1 == 0) goto L25
        L38:
            java.lang.String r8 = r2.B()
            java.lang.String r1 = r2.C()
            java.lang.String r5 = r2.j
            r7.j = r3
            com.quizlet.features.practicetest.takingtest.usecase.f r3 = r2.c
            java.lang.Object r8 = r3.e(r8, r1, r5, r7)
            if (r8 != r0) goto L4d
            goto L60
        L4d:
            java.lang.String r8 = (java.lang.String) r8
            kotlinx.coroutines.flow.d0 r1 = r2.m
            com.quizlet.features.practicetest.takingtest.data.C r3 = new com.quizlet.features.practicetest.takingtest.data.C
            java.lang.String r2 = r2.j
            r3.<init>(r8, r2)
            r7.j = r4
            java.lang.Object r8 = r1.emit(r3, r7)
            if (r8 != r0) goto L61
        L60:
            return r0
        L61:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.practicetest.takingtest.viewmodel.c.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
