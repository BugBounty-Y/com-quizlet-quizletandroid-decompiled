package androidx.compose.foundation.lazy.grid;

import androidx.compose.foundation.u0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class y extends kotlin.coroutines.jvm.internal.c {
    public A j;
    public u0 k;
    public Function2 l;
    public /* synthetic */ Object m;
    public final /* synthetic */ A n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public y(A a, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.c(null, null, this);
    }
}
