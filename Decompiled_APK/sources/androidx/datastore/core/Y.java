package androidx.datastore.core;

import java.io.FileOutputStream;

/* loaded from: classes.dex */
public final class Y extends kotlin.coroutines.jvm.internal.c {
    public FileOutputStream j;
    public FileOutputStream k;
    public /* synthetic */ Object l;
    public final /* synthetic */ Z m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Y(Z z, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.b(null, this);
    }
}
