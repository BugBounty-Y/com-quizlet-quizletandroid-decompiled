package kotlinx.coroutines.flow;

/* renamed from: kotlinx.coroutines.flow.u, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5012u extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;
    public final /* synthetic */ C5013v l;
    public Object m;
    public InterfaceC5002j n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C5012u(C5013v c5013v, kotlin.coroutines.h hVar) {
        super(hVar);
        this.l = c5013v;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return this.l.b(null, this);
    }
}
