package com.quizlet.features.notes.upload.viewmodels;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public c j;
    public int k;
    public final /* synthetic */ c l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(c cVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new a(this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x0070, code lost:
    
        if (r7 != r0) goto L23;
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
            int r1 = r6.k
            r2 = 3
            r3 = 2
            r4 = 1
            com.quizlet.features.notes.upload.viewmodels.c r5 = r6.l
            if (r1 == 0) goto L2b
            if (r1 == r4) goto L25
            if (r1 == r3) goto L1f
            if (r1 != r2) goto L17
            com.quizlet.features.notes.upload.viewmodels.c r5 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L73
        L17:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1f:
            com.quizlet.features.notes.upload.viewmodels.c r1 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L5a
        L25:
            com.quizlet.features.notes.upload.viewmodels.c r1 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L40
        L2b:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.data.repository.explanations.question.a r7 = r5.h
            r6.j = r5
            r6.k = r4
            java.lang.Object r1 = r7.c
            java.lang.Integer r1 = (java.lang.Integer) r1
            java.lang.Object r7 = r7.d(r1)
            if (r7 != r0) goto L3f
            goto L72
        L3f:
            r1 = r5
        L40:
            java.lang.Number r7 = (java.lang.Number) r7
            int r7 = r7.intValue()
            r1.m = r7
            com.quizlet.data.repository.explanations.question.a r7 = r5.g
            r6.j = r5
            r6.k = r3
            java.lang.Object r1 = r7.c
            java.lang.Integer r1 = (java.lang.Integer) r1
            java.lang.Object r7 = r7.d(r1)
            if (r7 != r0) goto L59
            goto L72
        L59:
            r1 = r5
        L5a:
            java.lang.Number r7 = (java.lang.Number) r7
            int r7 = r7.intValue()
            r1.n = r7
            com.quizlet.data.repository.explanations.question.a r7 = r5.i
            r6.j = r5
            r6.k = r2
            java.lang.Object r1 = r7.c
            java.lang.Integer r1 = (java.lang.Integer) r1
            java.lang.Object r7 = r7.d(r1)
            if (r7 != r0) goto L73
        L72:
            return r0
        L73:
            java.lang.Number r7 = (java.lang.Number) r7
            int r7 = r7.intValue()
            r5.o = r7
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.notes.upload.viewmodels.a.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
