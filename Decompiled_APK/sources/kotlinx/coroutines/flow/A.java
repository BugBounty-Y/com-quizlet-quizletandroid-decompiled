package kotlinx.coroutines.flow;

/* loaded from: classes3.dex */
public final class A extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;
    public final /* synthetic */ androidx.compose.material3.internal.H l;
    public androidx.compose.material3.internal.H m;
    public InterfaceC5002j n;
    public Throwable o;
    public long p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(androidx.compose.material3.internal.H h, kotlin.coroutines.h hVar) {
        super(hVar);
        this.l = h;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return this.l.b(null, this);
    }
}
