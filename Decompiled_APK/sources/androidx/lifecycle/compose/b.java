package androidx.lifecycle.compose;

import androidx.compose.runtime.C0807l0;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.a0;

/* loaded from: classes.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ CoroutineContext k;
    public final /* synthetic */ a0 l;
    public final /* synthetic */ C0807l0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(CoroutineContext coroutineContext, a0 a0Var, C0807l0 c0807l0, h hVar) {
        super(2, hVar);
        this.k = coroutineContext;
        this.l = a0Var;
        this.m = c0807l0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0036, code lost:
    
        if (r5.b(r7, r6) == r0) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0045, code lost:
    
        if (kotlinx.coroutines.E.J(r1, r7, r6) == r0) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x0047, code lost:
    
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
            goto L48
        L19:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.coroutines.n r7 = kotlin.coroutines.n.a
            kotlin.coroutines.CoroutineContext r1 = r6.k
            boolean r7 = kotlin.jvm.internal.Intrinsics.b(r1, r7)
            androidx.compose.runtime.l0 r4 = r6.m
            kotlinx.coroutines.flow.a0 r5 = r6.l
            if (r7 == 0) goto L39
            androidx.compose.material.navigation.e r7 = new androidx.compose.material.navigation.e
            r1 = 3
            r7.<init>(r4, r1)
            r6.j = r3
            java.lang.Object r7 = r5.b(r7, r6)
            if (r7 != r0) goto L48
            goto L47
        L39:
            androidx.lifecycle.compose.a r7 = new androidx.lifecycle.compose.a
            r3 = 0
            r7.<init>(r5, r4, r3)
            r6.j = r2
            java.lang.Object r7 = kotlinx.coroutines.E.J(r1, r7, r6)
            if (r7 != r0) goto L48
        L47:
            return r0
        L48:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.lifecycle.compose.b.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
