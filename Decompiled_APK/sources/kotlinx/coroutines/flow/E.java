package kotlinx.coroutines.flow;

import androidx.paging.I0;
import androidx.paging.J0;

/* loaded from: classes3.dex */
public final class E extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;
    public final /* synthetic */ J0 l;
    public I0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E(J0 j0, kotlin.coroutines.h hVar) {
        super(hVar);
        this.l = j0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return this.l.b(null, this);
    }
}
