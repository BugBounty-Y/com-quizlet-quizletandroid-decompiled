package androidx.paging.compose;

import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ CoroutineContext k;
    public final /* synthetic */ d l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(CoroutineContext coroutineContext, d dVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = coroutineContext;
        this.l = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x003e, code lost:
    
        if (r7 == r0) goto L20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x004c, code lost:
    
        if (kotlinx.coroutines.E.J(r1, r7, r6) == r0) goto L20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x004e, code lost:
    
        return r0;
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
            if (r1 == 0) goto L19
            if (r1 == r3) goto L15
            if (r1 != r2) goto Ld
            goto L15
        Ld:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L15:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4f
        L19:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.coroutines.n r7 = kotlin.coroutines.n.a
            kotlin.coroutines.CoroutineContext r1 = r6.k
            boolean r7 = kotlin.jvm.internal.Intrinsics.b(r1, r7)
            r4 = 0
            androidx.paging.compose.d r5 = r6.l
            if (r7 == 0) goto L41
            r6.j = r3
            r5.getClass()
            androidx.paging.compose.b r7 = new androidx.paging.compose.b
            r7.<init>(r5, r4)
            kotlinx.coroutines.flow.i r1 = r5.a
            java.lang.Object r7 = kotlinx.coroutines.flow.e0.i(r1, r7, r6)
            if (r7 != r0) goto L3c
            goto L3e
        L3c:
            kotlin.Unit r7 = kotlin.Unit.a
        L3e:
            if (r7 != r0) goto L4f
            goto L4e
        L41:
            androidx.paging.compose.e r7 = new androidx.paging.compose.e
            r7.<init>(r5, r4)
            r6.j = r2
            java.lang.Object r7 = kotlinx.coroutines.E.J(r1, r7, r6)
            if (r7 != r0) goto L4f
        L4e:
            return r0
        L4f:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.compose.f.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
