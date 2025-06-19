package androidx.paging;

import androidx.appcompat.widget.C0122z;

/* renamed from: androidx.paging.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1331o extends kotlin.coroutines.jvm.internal.c {
    public C0122z j;
    public kotlinx.coroutines.sync.c k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C0122z m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1331o(C0122z c0122z, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = c0122z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.r(this);
    }
}
