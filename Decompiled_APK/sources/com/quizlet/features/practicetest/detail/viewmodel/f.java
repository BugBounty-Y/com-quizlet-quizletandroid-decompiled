package com.quizlet.features.practicetest.detail.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ i k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(i iVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:0x0059, code lost:
    
        if (com.quizlet.features.practicetest.detail.viewmodel.i.A(r4, r5) == r0) goto L21;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.j
            r2 = 2
            r3 = 1
            com.quizlet.features.practicetest.detail.viewmodel.i r4 = r5.k
            if (r1 == 0) goto L1e
            if (r1 == r3) goto L1a
            if (r1 != r2) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L5c
        L12:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L2c
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            androidx.work.impl.model.e r6 = r4.f
            r5.j = r3
            java.lang.Object r6 = r6.l(r5)
            if (r6 != r0) goto L2c
            goto L5b
        L2c:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            com.quizlet.db.data.caches.UserInfoCache r1 = r4.g
            boolean r1 = r1.b()
            if (r1 == 0) goto L53
            if (r6 != 0) goto L53
        L3c:
            kotlinx.coroutines.flow.s0 r6 = r4.l
            java.lang.Object r0 = r6.getValue()
            r1 = r0
            com.quizlet.features.practicetest.detail.data.I r1 = (com.quizlet.features.practicetest.detail.data.I) r1
            com.quizlet.features.practicetest.detail.data.G r1 = new com.quizlet.features.practicetest.detail.data.G
            com.quizlet.features.practicetest.common.data.g r2 = com.quizlet.features.practicetest.common.data.g.a
            r1.<init>(r2)
            boolean r6 = r6.k(r0, r1)
            if (r6 == 0) goto L3c
            goto L5c
        L53:
            r5.j = r2
            java.lang.Object r6 = com.quizlet.features.practicetest.detail.viewmodel.i.A(r4, r5)
            if (r6 != r0) goto L5c
        L5b:
            return r0
        L5c:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.practicetest.detail.viewmodel.f.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
