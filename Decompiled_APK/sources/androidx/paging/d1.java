package androidx.paging;

import com.google.android.gms.internal.ads.C2580rn;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class d1 extends kotlin.coroutines.jvm.internal.c {
    public C2580rn j;
    public InterfaceC5025j0 k;
    public kotlinx.coroutines.sync.a l;
    public int m;
    public /* synthetic */ Object n;
    public final /* synthetic */ C2580rn o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d1(C2580rn c2580rn, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = c2580rn;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.b(0, null, this);
    }
}
