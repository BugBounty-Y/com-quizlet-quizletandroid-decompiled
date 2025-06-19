package com.quizlet.features.questiontypes.written;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ o k;
    public final /* synthetic */ com.quizlet.features.questiontypes.written.data.a l;
    public final /* synthetic */ String m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(o oVar, com.quizlet.features.questiontypes.written.data.a aVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = oVar;
        this.l = aVar;
        this.m = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x003c  */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0049 A[RETURN] */
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
            java.lang.String r2 = r6.m
            com.quizlet.features.questiontypes.written.data.a r3 = r6.l
            com.quizlet.features.questiontypes.written.o r4 = r6.k
            r5 = 1
            if (r1 == 0) goto L1b
            if (r1 != r5) goto L13
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4a
        L13:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1b:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.studiablemodels.grading.b r7 = r4.o
            r6.j = r5
            if (r3 != 0) goto L3c
            if (r7 == 0) goto L3c
            com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer r1 = r7.a
            com.quizlet.studiablemodels.grading.StudiableQuestionFeedback r1 = r1.b
            com.quizlet.studiablemodels.grading.StudiableQuestionResponse r1 = r1.a
            java.lang.String r5 = "null cannot be cast to non-null type com.quizlet.studiablemodels.grading.WrittenResponse"
            kotlin.jvm.internal.Intrinsics.e(r1, r5)
            com.quizlet.studiablemodels.grading.WrittenResponse r1 = (com.quizlet.studiablemodels.grading.WrittenResponse) r1
            java.lang.String r1 = r1.a
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r1, r2)
            if (r1 == 0) goto L3c
            goto L47
        L3c:
            com.quizlet.studiablemodels.grading.WrittenResponse r7 = new com.quizlet.studiablemodels.grading.WrittenResponse
            r7.<init>(r2)
            androidx.work.impl.model.l r1 = r4.b
            java.lang.Object r7 = r1.k(r7, r6)
        L47:
            if (r7 != r0) goto L4a
            return r0
        L4a:
            com.quizlet.studiablemodels.grading.b r7 = (com.quizlet.studiablemodels.grading.b) r7
            r4.o = r7
            r4.C(r3, r2, r7)
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questiontypes.written.j.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
