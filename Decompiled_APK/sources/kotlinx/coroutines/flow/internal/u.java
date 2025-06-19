package kotlinx.coroutines.flow.internal;

import kotlinx.coroutines.flow.C5009q;

/* loaded from: classes3.dex */
public final class u extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ C5009q k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(C5009q c5009q, kotlin.coroutines.h hVar) {
        super(hVar);
        this.k = c5009q;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.emit(null, this);
    }
}
