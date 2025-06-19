package androidx.glance.state;

import java.io.Serializable;

/* loaded from: classes.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public Object k;
    public Serializable l;
    public kotlinx.coroutines.sync.c m;
    public /* synthetic */ Object n;
    public final /* synthetic */ f o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(f fVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.b(null, null, null, this);
    }
}
