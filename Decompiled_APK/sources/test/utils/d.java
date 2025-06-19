package test.utils;

import com.google.android.gms.ads.internal.client.C1608n;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.c {
    public C1608n j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C1608n m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(C1608n c1608n, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = c1608n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.q(null, this);
    }
}
