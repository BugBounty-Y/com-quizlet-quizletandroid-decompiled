package com.quizlet.features.questionnaire.navigation;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ m l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(m mVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        j jVar = new j(this.l, hVar);
        jVar.k = obj;
        return jVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((q) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0035, code lost:
    
        if (com.quizlet.features.questionnaire.navigation.m.A(r5, r7.b, r6) == r0) goto L25;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x0048, code lost:
    
        if (com.quizlet.features.questionnaire.navigation.m.A(r5, r7.b, r6) == r0) goto L25;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x005b, code lost:
    
        if (com.quizlet.features.questionnaire.navigation.m.A(r5, r7.b, r6) == r0) goto L25;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x005d, code lost:
    
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
            r2 = 3
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1c
            if (r1 == r4) goto L18
            if (r1 == r3) goto L18
            if (r1 != r2) goto L10
            goto L18
        L10:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L18:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L5e
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r6.k
            com.quizlet.features.questionnaire.navigation.q r7 = (com.quizlet.features.questionnaire.navigation.q) r7
            boolean r1 = r7 instanceof com.quizlet.features.questionnaire.navigation.o
            com.quizlet.features.questionnaire.navigation.m r5 = r6.l
            if (r1 == 0) goto L38
            com.quizlet.features.questionnaire.navigation.o r7 = (com.quizlet.features.questionnaire.navigation.o) r7
            java.lang.String r1 = r7.a
            r6.j = r4
            java.lang.String r7 = r7.b
            java.lang.Object r7 = com.quizlet.features.questionnaire.navigation.m.A(r5, r7, r6)
            if (r7 != r0) goto L5e
            goto L5d
        L38:
            boolean r1 = r7 instanceof com.quizlet.features.questionnaire.navigation.p
            if (r1 == 0) goto L4b
            com.quizlet.features.questionnaire.navigation.p r7 = (com.quizlet.features.questionnaire.navigation.p) r7
            java.lang.String r1 = r7.a
            r6.j = r3
            java.lang.String r7 = r7.b
            java.lang.Object r7 = com.quizlet.features.questionnaire.navigation.m.A(r5, r7, r6)
            if (r7 != r0) goto L5e
            goto L5d
        L4b:
            boolean r1 = r7 instanceof com.quizlet.features.questionnaire.navigation.n
            if (r1 == 0) goto L61
            com.quizlet.features.questionnaire.navigation.n r7 = (com.quizlet.features.questionnaire.navigation.n) r7
            java.lang.String r1 = r7.a
            r6.j = r2
            java.lang.String r7 = r7.b
            java.lang.Object r7 = com.quizlet.features.questionnaire.navigation.m.A(r5, r7, r6)
            if (r7 != r0) goto L5e
        L5d:
            return r0
        L5e:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        L61:
            kotlin.NoWhenBranchMatchedException r7 = new kotlin.NoWhenBranchMatchedException
            r7.<init>()
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questionnaire.navigation.j.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
