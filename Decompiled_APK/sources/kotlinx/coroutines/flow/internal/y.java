package kotlinx.coroutines.flow.internal;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.C5010s;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class y extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C5010s l;
    public final /* synthetic */ InterfaceC5002j m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public y(C5010s c5010s, InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c5010s;
        this.m = interfaceC5002j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        y yVar = new y(this.l, this.m, hVar);
        yVar.k = obj;
        return yVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((y) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.k;
            this.j = 1;
            if (this.l.invoke(c, this.m, this) == aVar) {
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
