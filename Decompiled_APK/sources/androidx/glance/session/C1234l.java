package androidx.glance.session;

import kotlin.jvm.functions.Function2;

/* renamed from: androidx.glance.session.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1234l extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public Function2 k;
    public kotlinx.coroutines.sync.c l;
    public /* synthetic */ Object m;
    public final /* synthetic */ p n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1234l(p pVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = pVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.a(null, this);
    }
}
