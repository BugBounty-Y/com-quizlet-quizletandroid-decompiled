package androidx.paging;

import kotlin.Unit;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes.dex */
public final class X extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public int j;
    public /* synthetic */ InterfaceC5002j k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C1336q0 m;
    public final /* synthetic */ G n;
    public kotlinx.coroutines.sync.c o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public X(kotlin.coroutines.h hVar, C1336q0 c1336q0, G g) {
        super(3, hVar);
        this.m = c1336q0;
        this.n = g;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        X x = new X((kotlin.coroutines.h) obj3, this.m, this.n);
        x.k = (InterfaceC5002j) obj;
        x.l = obj2;
        return x.invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:40:0x00ce, code lost:
    
        if (r13 == r4) goto L41;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 221
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.X.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
