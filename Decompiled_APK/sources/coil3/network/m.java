package coil3.network;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ q l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(q qVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = qVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        m mVar = new m(this.l, hVar);
        mVar.k = obj;
        return mVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((m) create((t) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        t tVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        q qVar = this.l;
        if (i == 0) {
            Z.e(obj);
            t tVar2 = (t) this.k;
            u uVar = tVar2.e;
            if (uVar == null) {
                throw new IllegalStateException("body == null");
            }
            this.k = tVar2;
            this.j = 1;
            Object objB = q.b(qVar, uVar, this);
            if (objB == aVar) {
                return aVar;
            }
            tVar = tVar2;
            obj = objB;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            tVar = (t) this.k;
            Z.e(obj);
        }
        return new coil3.fetch.i((coil3.decode.q) obj, q.f(qVar.a, tVar.d.a()), coil3.decode.h.d);
    }
}
