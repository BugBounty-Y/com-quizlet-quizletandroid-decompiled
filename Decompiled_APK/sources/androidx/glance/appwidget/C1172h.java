package androidx.glance.appwidget;

import android.content.Context;

/* renamed from: androidx.glance.appwidget.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1172h extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public Context k;
    public androidx.glance.m l;
    public /* synthetic */ Object m;
    public final /* synthetic */ C1182m n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1172h(C1182m c1182m, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = c1182m;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.b(null, null, this);
    }
}
