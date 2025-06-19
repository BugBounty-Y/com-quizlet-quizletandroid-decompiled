package androidx.compose.foundation.pager;

import androidx.compose.animation.core.InterfaceC0256n;

/* loaded from: classes.dex */
public final class A extends kotlin.coroutines.jvm.internal.c {
    public E j;
    public InterfaceC0256n k;
    public int l;
    public /* synthetic */ Object m;
    public final /* synthetic */ E n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(E e, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = e;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.f(0, null, this);
    }
}
