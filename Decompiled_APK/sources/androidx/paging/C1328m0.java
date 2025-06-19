package androidx.paging;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.paging.m0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1328m0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public Object k;
    public kotlinx.coroutines.sync.c l;
    public int m;
    public /* synthetic */ Object n;
    public final /* synthetic */ C1336q0 o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1328m0(C1336q0 c1336q0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.o = c1336q0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1328m0 c1328m0 = new C1328m0(this.o, hVar);
        c1328m0.n = obj;
        return c1328m0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1328m0) create((a1) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x00c2  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) {
        /*
            Method dump skipped, instructions count: 215
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.C1328m0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
