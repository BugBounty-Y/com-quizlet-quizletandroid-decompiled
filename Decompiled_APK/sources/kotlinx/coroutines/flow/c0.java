package kotlinx.coroutines.flow;

import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes3.dex */
public final class c0 extends kotlin.coroutines.jvm.internal.c {
    public d0 j;
    public InterfaceC5002j k;
    public f0 l;
    public InterfaceC5025j0 m;
    public /* synthetic */ Object n;
    public final /* synthetic */ d0 o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c0(d0 d0Var, kotlin.coroutines.h hVar) {
        super(hVar);
        this.o = d0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        d0.m(this.o, null, this);
        return kotlin.coroutines.intrinsics.a.a;
    }
}
