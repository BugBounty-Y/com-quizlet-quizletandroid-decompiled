package kotlinx.coroutines.flow;

import androidx.paging.C1307c;

/* loaded from: classes3.dex */
public final class U extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ C1307c k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public U(C1307c c1307c, kotlin.coroutines.h hVar) {
        super(hVar);
        this.k = c1307c;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.emit(null, this);
    }
}
