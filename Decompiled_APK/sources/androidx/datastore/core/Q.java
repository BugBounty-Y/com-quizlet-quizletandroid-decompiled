package androidx.datastore.core;

import java.io.FileInputStream;

/* loaded from: classes.dex */
public final class Q extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public FileInputStream k;
    public /* synthetic */ Object l;
    public final /* synthetic */ S m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Q(S s, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = s;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return S.f(this.m, this);
    }
}
