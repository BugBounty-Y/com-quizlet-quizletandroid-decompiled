package androidx.compose.runtime;

import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes.dex */
public final class T0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ CoroutineContext l;
    public final /* synthetic */ InterfaceC4992i m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public T0(CoroutineContext coroutineContext, InterfaceC4992i interfaceC4992i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = coroutineContext;
        this.m = interfaceC4992i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        T0 t0 = new T0(this.l, this.m, hVar);
        t0.k = obj;
        return t0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((T0) create((C0807l0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0038, code lost:
    
        if (r5.b(r1, r6) == r0) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0047, code lost:
    
        if (kotlinx.coroutines.E.J(r4, r1, r6) == r0) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x0049, code lost:
    
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
            goto L4a
        L19:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r6.k
            androidx.compose.runtime.l0 r7 = (androidx.compose.runtime.C0807l0) r7
            kotlin.coroutines.n r1 = kotlin.coroutines.n.a
            kotlin.coroutines.CoroutineContext r4 = r6.l
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r4, r1)
            kotlinx.coroutines.flow.i r5 = r6.m
            if (r1 == 0) goto L3b
            androidx.compose.material.navigation.e r1 = new androidx.compose.material.navigation.e
            r2 = 1
            r1.<init>(r7, r2)
            r6.j = r3
            java.lang.Object r7 = r5.b(r1, r6)
            if (r7 != r0) goto L4a
            goto L49
        L3b:
            androidx.compose.runtime.S0 r1 = new androidx.compose.runtime.S0
            r3 = 0
            r1.<init>(r5, r7, r3)
            r6.j = r2
            java.lang.Object r7 = kotlinx.coroutines.E.J(r4, r1, r6)
            if (r7 != r0) goto L4a
        L49:
            return r0
        L4a:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.T0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
