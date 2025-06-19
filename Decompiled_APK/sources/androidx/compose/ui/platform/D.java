package androidx.compose.ui.platform;

import androidx.collection.C0224w;

/* loaded from: classes.dex */
public final class D extends kotlin.coroutines.jvm.internal.c {
    public F j;
    public C0224w k;
    public kotlinx.coroutines.channels.c l;
    public /* synthetic */ Object m;
    public final /* synthetic */ F n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(F f, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = f;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.l(this);
    }
}
