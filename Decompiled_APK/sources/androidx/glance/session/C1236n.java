package androidx.glance.session;

import android.content.Context;

/* renamed from: androidx.glance.session.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1236n extends kotlin.coroutines.jvm.internal.c {
    public o j;
    public Context k;
    public /* synthetic */ Object l;
    public final /* synthetic */ o m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1236n(o oVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = oVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.b(null, null, this);
    }
}
