package com.quizlet.features.flashcards.autoplay;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.features.flashcards.data.b k;
    public final /* synthetic */ FlashcardsAutoplayService l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(com.quizlet.features.flashcards.data.b bVar, FlashcardsAutoplayService flashcardsAutoplayService, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = bVar;
        this.l = flashcardsAutoplayService;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new l(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((l) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:27:0x004f, code lost:
    
        if (kotlinx.coroutines.flow.e0.i(r8, r1, r7) == r0) goto L28;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.j
            com.quizlet.features.flashcards.autoplay.FlashcardsAutoplayService r2 = r7.l
            r3 = 2
            r4 = 1
            r5 = 0
            if (r1 == 0) goto L1f
            if (r1 == r4) goto L1b
            if (r1 != r3) goto L13
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L52
        L13:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1b:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L3c
        L1f:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.features.flashcards.data.b r8 = r7.k
            if (r8 == 0) goto L28
            r1 = r8
            goto L29
        L28:
            r1 = r5
        L29:
            if (r1 == 0) goto L2e
            com.quizlet.features.infra.models.flashcards.h r1 = r1.g
            goto L2f
        L2e:
            r1 = r5
        L2f:
            com.quizlet.features.infra.models.flashcards.h r6 = com.quizlet.features.infra.models.flashcards.h.b
            if (r1 != r6) goto L3c
            r7.j = r4
            java.lang.Object r8 = com.quizlet.features.flashcards.autoplay.FlashcardsAutoplayService.a(r2, r8, r7)
            if (r8 != r0) goto L3c
            goto L51
        L3c:
            com.quizlet.features.flashcards.engine.h r8 = r2.j
            if (r8 == 0) goto L52
            kotlinx.coroutines.flow.s0 r8 = r8.s
            if (r8 == 0) goto L52
            com.quizlet.features.flashcards.autoplay.k r1 = new com.quizlet.features.flashcards.autoplay.k
            r1.<init>(r2, r5)
            r7.j = r3
            java.lang.Object r8 = kotlinx.coroutines.flow.e0.i(r8, r1, r7)
            if (r8 != r0) goto L52
        L51:
            return r0
        L52:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.autoplay.l.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
