package test.utils;

import com.google.android.gms.ads.internal.client.C1608n;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public metering.manager.a j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C1608n l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(C1608n c1608n, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = c1608n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.r(null, this);
    }
}
