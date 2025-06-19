package kotlinx.coroutines.flow;

/* loaded from: classes3.dex */
public final class B extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ C k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(C c, kotlin.coroutines.h hVar) {
        super(hVar);
        this.k = c;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.emit(null, this);
    }
}
