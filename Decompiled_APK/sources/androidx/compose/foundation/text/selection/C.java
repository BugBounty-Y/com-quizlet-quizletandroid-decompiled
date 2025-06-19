package androidx.compose.foundation.text.selection;

import androidx.appcompat.widget.C0122z;
import androidx.compose.foundation.gestures.AbstractC0349s0;
import androidx.compose.foundation.text.u0;
import androidx.compose.ui.node.AbstractC0910f;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class C extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ InterfaceC0530k l;
    public final /* synthetic */ u0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(InterfaceC0530k interfaceC0530k, u0 u0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = interfaceC0530k;
        this.m = u0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C c = new C(this.l, this.m, hVar);
        c.k = obj;
        return c;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C) create((androidx.compose.ui.input.pointer.B) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            androidx.compose.ui.input.pointer.B b = (androidx.compose.ui.input.pointer.B) this.k;
            b.getClass();
            B b2 = new B(this.l, new C0122z(AbstractC0910f.v(b).t), this.m, null);
            this.j = 1;
            if (AbstractC0349s0.d(b, b2, this) == aVar) {
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
