package androidx.compose.foundation.text.selection;

import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.foundation.text.u0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class k0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ u0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k0(u0 u0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = u0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        k0 k0Var = new k0(this.l, hVar);
        k0Var.k = obj;
        return k0Var;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k0) create((androidx.compose.ui.input.pointer.B) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            androidx.compose.ui.input.pointer.B b = (androidx.compose.ui.input.pointer.B) this.k;
            this.j = 1;
            if (AbstractC0484d0.r(b, this.l, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
