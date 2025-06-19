package com.quizlet.features.flashcards;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class J extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ S k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public J(S s, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = s;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new J(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((J) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0034, code lost:
    
        if (r6.k(r5) == r0) goto L15;
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
            com.quizlet.features.flashcards.S r2 = r5.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L37
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
            com.quizlet.features.flashcards.engine.h r6 = r2.c
            r5.j = r4
            java.lang.Object r6 = r6.h(r5)
            if (r6 != r0) goto L2c
            goto L36
        L2c:
            com.quizlet.features.flashcards.engine.h r6 = r2.c
            r5.j = r3
            java.lang.Object r6 = r6.k(r5)
            if (r6 != r0) goto L37
        L36:
            return r0
        L37:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.J.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
