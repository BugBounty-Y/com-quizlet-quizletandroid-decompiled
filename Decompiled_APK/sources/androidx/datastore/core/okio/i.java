package androidx.datastore.core.okio;

import okio.s;
import okio.z;

/* loaded from: classes.dex */
public final class i extends kotlin.coroutines.jvm.internal.c {
    public s j;
    public s k;
    public z l;
    public /* synthetic */ Object m;
    public final /* synthetic */ j n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(j jVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.b(null, this);
    }
}
