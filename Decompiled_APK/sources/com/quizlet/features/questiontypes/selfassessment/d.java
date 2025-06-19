package com.quizlet.features.questiontypes.selfassessment;

import com.quizlet.db.data.models.persisted.DBAnswer;
import java.util.List;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public int j;
    public final /* synthetic */ h k;
    public final /* synthetic */ DBAnswer l;
    public final /* synthetic */ List m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(h hVar, DBAnswer dBAnswer, List list, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = hVar;
        this.l = dBAnswer;
        this.m = list;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0042, code lost:
    
        if (r7.emit(r1, r6) == r0) goto L15;
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
            if (r1 == 0) goto L1c
            if (r1 == r3) goto L18
            if (r1 != r2) goto L10
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L45
        L10:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L18:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L2a
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r6.j = r3
            r3 = 300(0x12c, double:1.48E-321)
            java.lang.Object r7 = kotlinx.coroutines.E.n(r3, r6)
            if (r7 != r0) goto L2a
            goto L44
        L2a:
            com.quizlet.features.questiontypes.selfassessment.h r7 = r6.k
            kotlinx.coroutines.flow.d0 r7 = r7.l
            com.quizlet.features.questiontypes.basequestion.g r1 = new com.quizlet.features.questiontypes.basequestion.g
            com.quizlet.features.questiontypes.basequestion.data.b r3 = new com.quizlet.features.questiontypes.basequestion.data.b
            com.quizlet.db.data.models.persisted.DBAnswer r4 = r6.l
            java.util.List r5 = r6.m
            r3.<init>(r4, r5)
            r1.<init>(r3)
            r6.j = r2
            java.lang.Object r7 = r7.emit(r1, r6)
            if (r7 != r0) goto L45
        L44:
            return r0
        L45:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questiontypes.selfassessment.d.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
