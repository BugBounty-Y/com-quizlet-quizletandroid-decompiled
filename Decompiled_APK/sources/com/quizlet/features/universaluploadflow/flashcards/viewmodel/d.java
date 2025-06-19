package com.quizlet.features.universaluploadflow.flashcards.viewmodel;

import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public int j;
    public final /* synthetic */ e k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(e eVar, String str, h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new d(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x005b, code lost:
    
        if (r9 == r0) goto L22;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.j
            com.quizlet.features.universaluploadflow.flashcards.viewmodel.e r2 = r8.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L5e
        L12:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L4f
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            kotlinx.coroutines.flow.s0 r9 = r2.g
            java.lang.Object r1 = r9.getValue()
            boolean r5 = r1 instanceof com.quizlet.features.universaluploadflow.flashcards.data.p
            r6 = 0
            if (r5 == 0) goto L2f
            com.quizlet.features.universaluploadflow.flashcards.data.p r1 = (com.quizlet.features.universaluploadflow.flashcards.data.p) r1
            goto L30
        L2f:
            r1 = r6
        L30:
            if (r1 == 0) goto L44
        L32:
            java.lang.Object r5 = r9.getValue()
            r7 = r5
            com.quizlet.features.universaluploadflow.flashcards.data.s r7 = (com.quizlet.features.universaluploadflow.flashcards.data.s) r7
            r7 = 7
            com.quizlet.features.universaluploadflow.flashcards.data.p r7 = com.quizlet.features.universaluploadflow.flashcards.data.p.b(r1, r6, r7)
            boolean r5 = r9.k(r5, r7)
            if (r5 == 0) goto L32
        L44:
            r8.j = r4
            long r4 = r2.f
            java.lang.Object r9 = kotlinx.coroutines.E.n(r4, r8)
            if (r9 != r0) goto L4f
            goto L5d
        L4f:
            r8.j = r3
            java.lang.String r9 = r8.l
            r1 = 62
            androidx.compose.foundation.gestures.l1 r3 = r2.d
            java.io.Serializable r9 = androidx.compose.foundation.gestures.l1.C(r3, r9, r8, r1)
            if (r9 != r0) goto L5e
        L5d:
            return r0
        L5e:
            java.util.List r9 = (java.util.List) r9
            com.quizlet.features.universaluploadflow.flashcards.viewmodel.e.A(r2, r9)
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.universaluploadflow.flashcards.viewmodel.d.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
