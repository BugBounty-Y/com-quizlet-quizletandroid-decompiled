package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.C4179x0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.generated.enums.P;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class E extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ int k;
    public final /* synthetic */ int l;
    public final /* synthetic */ G m;
    public final /* synthetic */ boolean n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E(int i, int i2, G g, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = i;
        this.l = i2;
        this.m = g;
        this.n = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new E(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((E) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            G g = this.m;
            InterfaceC4176w0 interfaceC4176w0 = g.I;
            if (interfaceC4176w0 == null) {
                Intrinsics.m("testMeteredEvent");
                throw null;
            }
            P pC0 = interfaceC4176w0.c0();
            InterfaceC4176w0 interfaceC4176w02 = g.I;
            if (interfaceC4176w02 == null) {
                Intrinsics.m("testMeteredEvent");
                throw null;
            }
            Long lR = interfaceC4176w02.r();
            InterfaceC4176w0 interfaceC4176w03 = g.I;
            if (interfaceC4176w03 == null) {
                Intrinsics.m("testMeteredEvent");
                throw null;
            }
            long jI = interfaceC4176w03.i();
            InterfaceC4176w0 interfaceC4176w04 = g.I;
            if (interfaceC4176w04 == null) {
                Intrinsics.m("testMeteredEvent");
                throw null;
            }
            C4179x0 c4179x0 = new C4179x0(this.k, this.l, pC0, lR, jI, interfaceC4176w04.B());
            this.j = 1;
            if (g.f.n(c4179x0, this.n, this) == aVar) {
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
