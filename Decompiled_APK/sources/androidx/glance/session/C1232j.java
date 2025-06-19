package androidx.glance.session;

import android.content.Context;
import androidx.glance.appwidget.C1182m;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.glance.session.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1232j extends kotlin.coroutines.jvm.internal.c {
    public C1182m j;
    public Context k;
    public Function1 l;
    public kotlinx.coroutines.channels.c m;
    public /* synthetic */ Object n;
    public final /* synthetic */ C1182m o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1232j(C1182m c1182m, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = c1182m;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.d(null, null, this);
    }
}
