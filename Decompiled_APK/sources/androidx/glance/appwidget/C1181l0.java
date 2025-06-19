package androidx.glance.appwidget;

import android.content.Context;

/* renamed from: androidx.glance.appwidget.l0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1181l0 extends kotlin.coroutines.jvm.internal.c {
    public Context j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C1221y m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1181l0(C1221y c1221y, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = c1221y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.b(null, 0, this);
    }
}
