package kotlinx.coroutines.flow;

import androidx.paging.I0;

/* loaded from: classes3.dex */
public final class F extends kotlin.coroutines.jvm.internal.c {
    public I0 j;
    public /* synthetic */ Object k;
    public int l;
    public final /* synthetic */ I0 m;
    public Object n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F(I0 i0, kotlin.coroutines.h hVar) {
        super(hVar);
        this.m = i0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.l |= Integer.MIN_VALUE;
        return this.m.emit(null, this);
    }
}
