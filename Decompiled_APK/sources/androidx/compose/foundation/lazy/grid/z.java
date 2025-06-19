package androidx.compose.foundation.lazy.grid;

import androidx.compose.foundation.gestures.InterfaceC0334k0;
import androidx.compose.ui.node.E;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class z extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ A j;
    public final /* synthetic */ int k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public z(A a, int i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = a;
        this.k = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new z(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((z) create((InterfaceC0334k0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        A a = this.j;
        androidx.compose.foundation.lazy.s sVar = a.b;
        int iA = sVar.a();
        int i = this.k;
        if (iA != i || sVar.b() != 0) {
            a.k.f();
        }
        sVar.c(i, 0);
        sVar.e = null;
        E e = a.h;
        if (e != null) {
            e.k();
        }
        return Unit.a;
    }
}
