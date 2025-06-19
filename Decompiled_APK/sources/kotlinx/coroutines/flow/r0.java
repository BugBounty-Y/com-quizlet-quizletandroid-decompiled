package kotlinx.coroutines.flow;

import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes3.dex */
public final class r0 extends kotlin.coroutines.jvm.internal.c {
    public s0 j;
    public InterfaceC5002j k;
    public t0 l;
    public InterfaceC5025j0 m;
    public Object n;
    public /* synthetic */ Object o;
    public final /* synthetic */ s0 p;
    public int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r0(s0 s0Var, kotlin.coroutines.h hVar) {
        super(hVar);
        this.p = s0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        this.o = obj;
        this.q |= Integer.MIN_VALUE;
        this.p.b(null, this);
        return kotlin.coroutines.intrinsics.a.a;
    }
}
