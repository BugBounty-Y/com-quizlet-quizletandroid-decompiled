package androidx.glance.session;

import android.content.Context;
import androidx.glance.appwidget.C1182m;
import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.C5041z;

/* loaded from: classes.dex */
public final class y extends kotlin.coroutines.a implements kotlinx.coroutines.A {
    public final /* synthetic */ K a;
    public final /* synthetic */ C1182m b;
    public final /* synthetic */ Context c;

    /* JADX WARN: Illegal instructions before constructor call */
    public y(K k, C1182m c1182m, Context context) {
        C5041z c5041z = C5041z.a;
        this.a = k;
        this.b = c1182m;
        this.c = context;
        super(c5041z);
    }

    @Override // kotlinx.coroutines.A
    public final void handleException(CoroutineContext coroutineContext, Throwable th) {
        C1182m c1182m = this.b;
        Context context = this.c;
        K k = this.a;
        kotlinx.coroutines.E.A(k, null, null, new F(c1182m, context, th, k, null), 3);
    }
}
