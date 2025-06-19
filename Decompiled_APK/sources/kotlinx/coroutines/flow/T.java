package kotlinx.coroutines.flow;

import androidx.paging.I0;

/* loaded from: classes3.dex */
public final class T extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;
    public final /* synthetic */ I0 l;
    public Object m;
    public InterfaceC5002j n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public T(I0 i0, kotlin.coroutines.h hVar) {
        super(hVar);
        this.l = i0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return this.l.emit(null, this);
    }
}
