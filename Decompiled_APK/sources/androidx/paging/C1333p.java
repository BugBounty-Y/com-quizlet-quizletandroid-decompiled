package androidx.paging;

import androidx.appcompat.widget.C0122z;
import kotlin.collections.IndexedValue;

/* renamed from: androidx.paging.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1333p extends kotlin.coroutines.jvm.internal.c {
    public C0122z j;
    public IndexedValue k;
    public kotlinx.coroutines.sync.c l;
    public /* synthetic */ Object m;
    public final /* synthetic */ C0122z n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1333p(C0122z c0122z, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = c0122z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.w(null, this);
    }
}
