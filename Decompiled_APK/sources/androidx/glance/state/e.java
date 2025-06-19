package androidx.glance.state;

import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public Function2 j;
    public /* synthetic */ Object k;
    public final /* synthetic */ f l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(f fVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.d(null, null, null, null, this);
    }
}
