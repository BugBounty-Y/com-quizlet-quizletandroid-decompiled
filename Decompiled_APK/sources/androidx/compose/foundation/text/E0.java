package androidx.compose.foundation.text;

import androidx.compose.foundation.gestures.C0326g0;
import androidx.compose.foundation.gestures.U0;
import androidx.compose.foundation.gestures.k1;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class E0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ kotlinx.coroutines.C l;
    public final /* synthetic */ InterfaceC0773a0 m;
    public final /* synthetic */ androidx.compose.foundation.interaction.l n;
    public final /* synthetic */ InterfaceC0773a0 o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E0(kotlinx.coroutines.C c, InterfaceC0773a0 interfaceC0773a0, androidx.compose.foundation.interaction.l lVar, InterfaceC0773a0 interfaceC0773a02, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c;
        this.m = interfaceC0773a0;
        this.n = lVar;
        this.o = interfaceC0773a02;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        E0 e0 = new E0(this.l, this.m, this.n, this.o, hVar);
        e0.k = obj;
        return e0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((E0) create((androidx.compose.ui.input.pointer.B) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            androidx.compose.ui.input.pointer.B b = (androidx.compose.ui.input.pointer.B) this.k;
            D0 d0 = new D0(this.l, this.m, this.n, null);
            androidx.compose.foundation.gestures.T t = new androidx.compose.foundation.gestures.T(this.o, 5);
            this.j = 1;
            androidx.compose.foundation.gestures.S s = k1.a;
            Object objM = kotlinx.coroutines.E.m(new U0(b, d0, t, new C0326g0(b), null), this);
            if (objM != obj2) {
                objM = Unit.a;
            }
            if (objM == obj2) {
                return obj2;
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
