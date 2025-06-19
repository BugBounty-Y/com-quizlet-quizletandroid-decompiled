package androidx.paging;

import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes.dex */
public final class H0 extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;
    public InterfaceC5002j l;
    public final /* synthetic */ I0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public H0(I0 i0, kotlin.coroutines.h hVar) {
        super(hVar);
        this.m = i0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return this.m.emit(null, this);
    }
}
