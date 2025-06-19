package androidx.datastore.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class g0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public M j;
    public int k;
    public final /* synthetic */ com.quizlet.data.repository.explanations.question.a l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g0(com.quizlet.data.repository.explanations.question.a aVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g0(this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x0059, code lost:
    
        if (r1.invoke(r7, r6) != r0) goto L18;
     */
    /* JADX WARN: Removed duplicated region for block: B:15:0x0050 A[PHI: r1 r7
  0x0050: PHI (r1v1 androidx.datastore.core.M) = (r1v3 androidx.datastore.core.M), (r1v4 androidx.datastore.core.M) binds: [B:13:0x004d, B:9:0x001a] A[DONT_GENERATE, DONT_INLINE]
  0x0050: PHI (r7v7 java.lang.Object) = (r7v15 java.lang.Object), (r7v0 java.lang.Object) binds: [B:13:0x004d, B:9:0x001a] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:16:0x0059 -> B:18:0x005c). Please report as a decompilation issue!!! */
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
            r2 = 2
            r3 = 1
            com.quizlet.data.repository.explanations.question.a r4 = r6.l
            if (r1 == 0) goto L20
            if (r1 == r3) goto L1a
            if (r1 != r2) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L5c
        L12:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1a:
            androidx.datastore.core.M r1 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L50
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r4.d
            androidx.appcompat.app.Q r7 = (androidx.appcompat.app.Q) r7
            java.lang.Object r7 = r7.a
            java.util.concurrent.atomic.AtomicInteger r7 = (java.util.concurrent.atomic.AtomicInteger) r7
            int r7 = r7.get()
            if (r7 <= 0) goto L6d
        L31:
            java.lang.Object r7 = r4.a
            kotlinx.coroutines.C r7 = (kotlinx.coroutines.C) r7
            kotlin.coroutines.CoroutineContext r7 = r7.getCoroutineContext()
            kotlinx.coroutines.E.o(r7)
            java.lang.Object r7 = r4.b
            r1 = r7
            androidx.datastore.core.M r1 = (androidx.datastore.core.M) r1
            java.lang.Object r7 = r4.c
            kotlinx.coroutines.channels.h r7 = (kotlinx.coroutines.channels.h) r7
            r6.j = r1
            r6.k = r3
            java.lang.Object r7 = r7.c(r6)
            if (r7 != r0) goto L50
            goto L5b
        L50:
            r5 = 0
            r6.j = r5
            r6.k = r2
            java.lang.Object r7 = r1.invoke(r7, r6)
            if (r7 != r0) goto L5c
        L5b:
            return r0
        L5c:
            java.lang.Object r7 = r4.d
            androidx.appcompat.app.Q r7 = (androidx.appcompat.app.Q) r7
            java.lang.Object r7 = r7.a
            java.util.concurrent.atomic.AtomicInteger r7 = (java.util.concurrent.atomic.AtomicInteger) r7
            int r7 = r7.decrementAndGet()
            if (r7 != 0) goto L31
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        L6d:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "Check failed."
            r7.<init>(r0)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.g0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
