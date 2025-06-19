package kotlinx.coroutines.flow.internal;

import androidx.datastore.core.C1087t;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.C5009q;

/* loaded from: classes3.dex */
public final class v extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C1087t l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public v(C1087t c1087t, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c1087t;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        v vVar = new v(this.l, hVar);
        vVar.k = obj;
        return vVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((v) create((kotlinx.coroutines.channels.u) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C5009q c5009q = new C5009q((kotlinx.coroutines.channels.u) this.k, 1);
            this.j = 1;
            if (this.l.b(c5009q, this) == aVar) {
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
