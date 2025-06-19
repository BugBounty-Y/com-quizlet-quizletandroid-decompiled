package androidx.compose.foundation.text;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.text.n0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0510n0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ androidx.compose.ui.input.pointer.B k;
    public final /* synthetic */ u0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0510n0(androidx.compose.ui.input.pointer.B b, u0 u0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = b;
        this.l = u0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0510n0 c0510n0 = new C0510n0(this.k, this.l, hVar);
        c0510n0.j = obj;
        return c0510n0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0510n0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.j;
        kotlinx.coroutines.D d = kotlinx.coroutines.D.d;
        androidx.compose.ui.input.pointer.B b = this.k;
        u0 u0Var = this.l;
        kotlinx.coroutines.E.A(c, null, d, new C0506l0(b, u0Var, null), 1);
        return kotlinx.coroutines.E.A(c, null, d, new C0508m0(b, u0Var, null), 1);
    }
}
