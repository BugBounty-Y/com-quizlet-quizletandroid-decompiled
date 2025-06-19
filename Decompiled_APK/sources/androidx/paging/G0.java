package androidx.paging;

import java.util.List;

/* loaded from: classes.dex */
public final class G0 extends kotlin.coroutines.jvm.internal.c {
    public androidx.paging.compose.c j;
    public List k;
    public F l;
    public F m;
    public com.google.firebase.platforminfo.c n;
    public C1345v0 o;
    public int p;
    public int q;
    public boolean r;
    public /* synthetic */ Object s;
    public final /* synthetic */ androidx.paging.compose.c t;
    public int u;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G0(androidx.paging.compose.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.t = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.s = obj;
        this.u |= Integer.MIN_VALUE;
        return androidx.paging.compose.c.a(this.t, null, 0, 0, false, null, null, null, this);
    }
}
