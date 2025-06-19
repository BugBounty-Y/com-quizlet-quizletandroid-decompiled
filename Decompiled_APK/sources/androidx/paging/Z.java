package androidx.paging;

/* loaded from: classes.dex */
public final class Z extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;
    public final /* synthetic */ C1304a0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Z(C1304a0 c1304a0, kotlin.coroutines.h hVar) {
        super(hVar);
        this.l = c1304a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return this.l.emit(null, this);
    }
}
