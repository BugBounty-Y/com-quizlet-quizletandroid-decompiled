package androidx.compose.foundation.pager;

import androidx.compose.foundation.u0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class B extends kotlin.coroutines.jvm.internal.c {
    public E j;
    public u0 k;
    public Function2 l;
    public /* synthetic */ Object m;
    public final /* synthetic */ E n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(E e, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = e;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return E.r(this.n, null, null, this);
    }
}
