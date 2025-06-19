package com.quizlet.features.flashcards;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class O extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ S k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public O(S s, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = s;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new O(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((O) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0022  */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0047  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:15:0x0069 -> B:11:0x0022). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r21) {
        /*
            r20 = this;
            r0 = r20
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.j
            r3 = 3000(0xbb8, double:1.482E-320)
            com.quizlet.features.flashcards.S r5 = r0.k
            r6 = 2
            r7 = 1
            if (r2 == 0) goto L1f
            if (r2 == r7) goto L1b
            if (r2 != r6) goto L13
            goto L1f
        L13:
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r1.<init>(r2)
            throw r1
        L1b:
            androidx.glance.appwidget.protobuf.Z.e(r21)
            goto L47
        L1f:
            androidx.glance.appwidget.protobuf.Z.e(r21)
        L22:
            androidx.lifecycle.Y r2 = r5.t
            com.quizlet.features.flashcards.data.o r8 = r5.G()
            com.quizlet.features.flashcards.data.m r17 = com.quizlet.features.flashcards.data.m.b
            r16 = 0
            r18 = 0
            r9 = 0
            r10 = 0
            r11 = 0
            r12 = 0
            r13 = 0
            r14 = 0
            r15 = 0
            r19 = 767(0x2ff, float:1.075E-42)
            com.quizlet.features.flashcards.data.o r8 = com.quizlet.features.flashcards.data.o.a(r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19)
            r2.l(r8)
            r0.j = r7
            java.lang.Object r2 = kotlinx.coroutines.E.n(r3, r0)
            if (r2 != r1) goto L47
            goto L6b
        L47:
            androidx.lifecycle.Y r2 = r5.t
            com.quizlet.features.flashcards.data.o r8 = r5.G()
            com.quizlet.features.flashcards.data.m r17 = com.quizlet.features.flashcards.data.m.c
            r16 = 0
            r18 = 0
            r9 = 0
            r10 = 0
            r11 = 0
            r12 = 0
            r13 = 0
            r14 = 0
            r15 = 0
            r19 = 767(0x2ff, float:1.075E-42)
            com.quizlet.features.flashcards.data.o r8 = com.quizlet.features.flashcards.data.o.a(r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19)
            r2.l(r8)
            r0.j = r6
            java.lang.Object r2 = kotlinx.coroutines.E.n(r3, r0)
            if (r2 != r1) goto L22
        L6b:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.O.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
