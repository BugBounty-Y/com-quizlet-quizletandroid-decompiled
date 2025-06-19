package kotlinx.coroutines.flow;

import kotlin.KotlinNothingValueException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class m0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ kotlinx.coroutines.flow.internal.H l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m0(kotlinx.coroutines.flow.internal.H h, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = h;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        m0 m0Var = new m0(this.l, hVar);
        m0Var.k = obj;
        return m0Var;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) throws Throwable {
        ((m0) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
            throw new KotlinNothingValueException();
        }
        androidx.glance.appwidget.protobuf.Z.e(obj);
        l0 l0Var = new l0(new kotlin.jvm.internal.F(), (InterfaceC5002j) this.k);
        this.j = 1;
        this.l.b(l0Var, this);
        return aVar;
    }
}
