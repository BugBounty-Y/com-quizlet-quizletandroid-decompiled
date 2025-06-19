package kotlinx.coroutines.flow.internal;

import androidx.compose.foundation.K;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.c {
    public K j;
    public Object k;
    public /* synthetic */ Object l;
    public final /* synthetic */ K m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(K k, kotlin.coroutines.h hVar) {
        super(hVar);
        this.m = k;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.emit(null, this);
    }
}
