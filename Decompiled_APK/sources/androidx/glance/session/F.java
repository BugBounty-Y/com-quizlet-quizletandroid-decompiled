package androidx.glance.session;

import android.content.Context;
import androidx.glance.appwidget.C1182m;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class F extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C1182m k;
    public final /* synthetic */ Context l;
    public final /* synthetic */ Throwable m;
    public final /* synthetic */ K n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F(C1182m c1182m, Context context, Throwable th, K k, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c1182m;
        this.l = context;
        this.m = th;
        this.n = k;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new F(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((F) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        Throwable th = this.m;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            this.k.a(this.l, th);
            if (Unit.a == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        kotlinx.coroutines.E.i(this.n, kotlinx.coroutines.E.a("Error in composition effect coroutine", th));
        return Unit.a;
    }
}
