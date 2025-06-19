package androidx.glance.session;

import androidx.glance.appwidget.C1182m;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C1182m l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(C1182m c1182m, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c1182m;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        t tVar = new t(this.l, hVar);
        tVar.k = obj;
        return tVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((t) create((o) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            o oVar = (o) this.k;
            String str = this.l.a;
            this.j = 1;
            C1182m c1182m = (C1182m) oVar.a.remove(str);
            if (c1182m != null) {
                c1182m.c.i(null);
                c1182m.b.set(false);
                c1182m.l.j(null);
            }
            if (Unit.a == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
