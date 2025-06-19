package androidx.paging;

import java.util.Collection;
import java.util.Iterator;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class K extends kotlin.coroutines.jvm.internal.c {
    public Function2 j;
    public L k;
    public G l;
    public Collection m;
    public Iterator n;
    public g1 o;
    public int[] p;
    public Collection q;
    public Iterator r;
    public Collection s;
    public Collection t;
    public /* synthetic */ Object u;
    public final /* synthetic */ L v;
    public int w;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K(L l, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.v = l;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.u = obj;
        this.w |= Integer.MIN_VALUE;
        return this.v.a(null, this);
    }
}
