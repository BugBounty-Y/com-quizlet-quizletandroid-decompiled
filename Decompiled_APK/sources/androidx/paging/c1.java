package androidx.paging;

import com.google.android.gms.internal.ads.C2580rn;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class c1 extends kotlin.coroutines.jvm.internal.c {
    public C2580rn j;
    public InterfaceC5025j0 k;
    public kotlinx.coroutines.sync.c l;
    public /* synthetic */ Object m;
    public final /* synthetic */ C2580rn n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c1(C2580rn c2580rn, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = c2580rn;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.a(null, this);
    }
}
