package androidx.compose.foundation.text;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class Q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ androidx.compose.ui.input.pointer.B k;
    public final /* synthetic */ u0 l;
    public final /* synthetic */ androidx.compose.foundation.text.selection.i0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Q(androidx.compose.ui.input.pointer.B b, u0 u0Var, androidx.compose.foundation.text.selection.i0 i0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = b;
        this.l = u0Var;
        this.m = i0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        Q q = new Q(this.k, this.l, this.m, hVar);
        q.j = obj;
        return q;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((Q) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.j;
        kotlinx.coroutines.D d = kotlinx.coroutines.D.d;
        androidx.compose.ui.input.pointer.B b = this.k;
        kotlinx.coroutines.E.A(c, null, d, new O(b, this.l, null), 1);
        kotlinx.coroutines.E.A(c, null, d, new P(b, this.m, null), 1);
        return Unit.a;
    }
}
