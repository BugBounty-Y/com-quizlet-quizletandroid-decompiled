package kotlinx.coroutines.flow.internal;

import androidx.paging.C1304a0;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ C1304a0 k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(C1304a0 c1304a0, kotlin.coroutines.h hVar) {
        super(hVar);
        this.k = c1304a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.emit(null, this);
    }
}
