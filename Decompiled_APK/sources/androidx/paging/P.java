package androidx.paging;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes.dex */
public final class P extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        P p = new P(2, hVar);
        p.k = obj;
        return p;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((P) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        InterfaceC5002j interfaceC5002j;
        U0 u0;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            interfaceC5002j = (InterfaceC5002j) this.k;
            u0 = null;
        } else {
            if (i != 1) {
                if (i != 2) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
                return Unit.a;
            }
            interfaceC5002j = (InterfaceC5002j) this.k;
            androidx.glance.appwidget.protobuf.Z.e(obj);
            u0 = (U0) obj;
        }
        Boolean boolValueOf = Boolean.valueOf(u0 == U0.a);
        this.k = null;
        this.j = 2;
        if (interfaceC5002j.emit(boolValueOf, this) == aVar) {
            return aVar;
        }
        return Unit.a;
    }
}
