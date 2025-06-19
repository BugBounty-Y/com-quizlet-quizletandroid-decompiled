package androidx.glance.state;

import android.content.Context;

/* loaded from: classes.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public Context j;
    public g k;
    public String l;
    public kotlinx.coroutines.sync.c m;
    public /* synthetic */ Object n;
    public final /* synthetic */ f o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(f fVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.a(null, null, null, this);
    }
}
