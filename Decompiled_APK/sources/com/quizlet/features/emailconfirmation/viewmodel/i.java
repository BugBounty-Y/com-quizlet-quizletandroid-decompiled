package com.quizlet.features.emailconfirmation.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ m k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(m mVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0036, code lost:
    
        if (r6.emit(r1, r5) == r0) goto L15;
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
            com.quizlet.features.emailconfirmation.viewmodel.m r2 = r5.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L39
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
            com.google.mlkit.vision.documentscanner.internal.c r6 = r2.c
            r5.j = r4
            java.lang.Object r6 = r6.d(r5)
            if (r6 != r0) goto L2c
            goto L38
        L2c:
            kotlinx.coroutines.flow.d0 r6 = r2.g
            com.quizlet.features.emailconfirmation.data.events.b r1 = com.quizlet.features.emailconfirmation.data.events.b.a
            r5.j = r3
            java.lang.Object r6 = r6.emit(r1, r5)
            if (r6 != r0) goto L39
        L38:
            return r0
        L39:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.emailconfirmation.viewmodel.i.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
