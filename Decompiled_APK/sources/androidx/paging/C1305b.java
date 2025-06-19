package androidx.paging;

import kotlin.collections.IndexedValue;

/* renamed from: androidx.paging.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1305b extends kotlin.coroutines.jvm.internal.c {
    public C1307c j;
    public IndexedValue k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C1307c m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1305b(C1307c c1307c, kotlin.coroutines.h hVar) {
        super(hVar);
        this.m = c1307c;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.a(null, this);
    }
}
