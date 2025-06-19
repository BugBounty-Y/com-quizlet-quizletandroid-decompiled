package com.quizlet.quizletandroid.ui.library;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class Y extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ c0 k;
    public final /* synthetic */ long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Y(c0 c0Var, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0Var;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new Y(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((Y) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x0072, code lost:
    
        if (r10.emit(r1, r9) != r0) goto L27;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
        /*
            r9 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r9.j
            r2 = 2
            r3 = 1
            long r4 = r9.l
            com.quizlet.quizletandroid.ui.library.c0 r6 = r9.k
            if (r1 == 0) goto L22
            if (r1 == r3) goto L1c
            if (r1 != r2) goto L14
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L75
        L14:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.util.NoSuchElementException -> L20
            goto L75
        L20:
            r10 = move-exception
            goto L57
        L22:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            java.util.List r10 = r6.v     // Catch: java.util.NoSuchElementException -> L20
            java.util.Iterator r10 = r10.iterator()     // Catch: java.util.NoSuchElementException -> L20
        L2b:
            boolean r1 = r10.hasNext()     // Catch: java.util.NoSuchElementException -> L20
            if (r1 == 0) goto L4f
            java.lang.Object r1 = r10.next()     // Catch: java.util.NoSuchElementException -> L20
            r7 = r1
            com.quizlet.data.model.S1 r7 = (com.quizlet.data.model.S1) r7     // Catch: java.util.NoSuchElementException -> L20
            com.quizlet.data.model.I r7 = r7.a     // Catch: java.util.NoSuchElementException -> L20
            long r7 = r7.a     // Catch: java.util.NoSuchElementException -> L20
            int r7 = (r7 > r4 ? 1 : (r7 == r4 ? 0 : -1))
            if (r7 != 0) goto L2b
            com.quizlet.data.model.S1 r1 = (com.quizlet.data.model.S1) r1     // Catch: java.util.NoSuchElementException -> L20
            com.quizlet.ui.models.content.carditem.f r10 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3682n5.b(r1)     // Catch: java.util.NoSuchElementException -> L20
            r9.j = r3     // Catch: java.util.NoSuchElementException -> L20
            java.lang.Object r10 = com.quizlet.quizletandroid.ui.library.c0.A(r6, r10, r9)     // Catch: java.util.NoSuchElementException -> L20
            if (r10 != r0) goto L75
            goto L74
        L4f:
            java.util.NoSuchElementException r10 = new java.util.NoSuchElementException     // Catch: java.util.NoSuchElementException -> L20
            java.lang.String r1 = "Collection contains no element matching the predicate."
            r10.<init>(r1)     // Catch: java.util.NoSuchElementException -> L20
            throw r10     // Catch: java.util.NoSuchElementException -> L20
        L57:
            timber.log.a r1 = timber.log.c.a
            java.lang.String r3 = "cached StudySet not found for ID: "
            java.lang.String r3 = androidx.compose.animation.d0.n(r4, r3)
            r7 = 0
            java.lang.Object[] r7 = new java.lang.Object[r7]
            r1.q(r10, r3, r7)
            kotlinx.coroutines.flow.d0 r10 = r6.u
            com.quizlet.quizletandroid.ui.library.data.B r1 = new com.quizlet.quizletandroid.ui.library.data.B
            r1.<init>(r4)
            r9.j = r2
            java.lang.Object r10 = r10.emit(r1, r9)
            if (r10 != r0) goto L75
        L74:
            return r0
        L75:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.library.Y.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
