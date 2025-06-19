package androidx.compose.foundation.text;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class E extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ androidx.compose.foundation.relocation.c k;
    public final /* synthetic */ androidx.compose.ui.text.input.A l;
    public final /* synthetic */ C0492h0 m;
    public final /* synthetic */ K0 n;
    public final /* synthetic */ androidx.compose.ui.text.input.s o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E(androidx.compose.foundation.relocation.c cVar, androidx.compose.ui.text.input.A a, C0492h0 c0492h0, K0 k0, androidx.compose.ui.text.input.s sVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = cVar;
        this.l = a;
        this.m = c0492h0;
        this.n = k0;
        this.o = sVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new E(this.k, this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((E) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        androidx.compose.ui.geometry.c cVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            t0 t0Var = this.m.a;
            androidx.compose.ui.text.H h = this.n.a;
            this.j = 1;
            int iP = this.o.p(androidx.compose.ui.text.K.d(this.l.b));
            if (iP < h.a.a.a.length()) {
                cVar = h.b(iP);
            } else if (iP != 0) {
                cVar = h.b(iP - 1);
            } else {
                cVar = new androidx.compose.ui.geometry.c(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 1.0f, (int) (x0.a(t0Var.b, t0Var.g, t0Var.h, x0.a, 1) & 4294967295L));
            }
            Object objA = this.k.a(cVar, this);
            if (objA != aVar) {
                objA = Unit.a;
            }
            if (objA == aVar) {
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
