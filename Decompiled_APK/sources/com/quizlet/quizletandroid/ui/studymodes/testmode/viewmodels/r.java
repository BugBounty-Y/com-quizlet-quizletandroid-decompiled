package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class r extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ t k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(t tVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = tVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new r(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((r) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x0033, code lost:
    
        if (r6.emit(r2, r5) == r0) goto L19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x003e, code lost:
    
        if (r6.emit(r1, r5) == r0) goto L19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x0040, code lost:
    
        return r0;
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
            if (r1 == 0) goto L19
            if (r1 == r3) goto L15
            if (r1 != r2) goto Ld
            goto L15
        Ld:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L15:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L41
        L19:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t r6 = r5.k
            com.quizlet.studiablemodels.StudiableMeteringData r1 = r6.o
            kotlinx.coroutines.flow.d0 r6 = r6.j
            if (r1 == 0) goto L36
            boolean r4 = r1.f
            if (r4 != r3) goto L36
            com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.f r2 = new com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.f
            r2.<init>(r1)
            r5.j = r3
            java.lang.Object r6 = r6.emit(r2, r5)
            if (r6 != r0) goto L41
            goto L40
        L36:
            com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.g r1 = com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4765g.a
            r5.j = r2
            java.lang.Object r6 = r6.emit(r1, r5)
            if (r6 != r0) goto L41
        L40:
            return r0
        L41:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.r.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
