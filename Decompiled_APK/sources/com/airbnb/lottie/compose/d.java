package com.airbnb.lottie.compose;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlinx.coroutines.E;
import kotlinx.coroutines.u0;

/* loaded from: classes.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;
    public final /* synthetic */ h k;
    public final /* synthetic */ int l;
    public final /* synthetic */ int m;
    public final /* synthetic */ float n;
    public final /* synthetic */ com.airbnb.lottie.h o;
    public final /* synthetic */ float p;
    public final /* synthetic */ l q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(h hVar, int i, int i2, float f, com.airbnb.lottie.h hVar2, float f2, l lVar, kotlin.coroutines.h hVar3) {
        super(1, hVar3);
        this.k = hVar;
        this.l = i;
        this.m = i2;
        this.n = f;
        this.o = hVar2;
        this.p = f2;
        this.q = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new d(this.k, this.l, this.m, this.n, this.o, this.p, this.q, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((d) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        CoroutineContext coroutineContext;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        h hVar = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                hVar.g(this.l);
                InterfaceC0773a0 interfaceC0773a0 = hVar.c;
                int i2 = this.m;
                ((L0) interfaceC0773a0).setValue(Integer.valueOf(i2));
                InterfaceC0773a0 interfaceC0773a02 = hVar.d;
                Boolean bool = Boolean.FALSE;
                ((L0) interfaceC0773a02).setValue(bool);
                InterfaceC0773a0 interfaceC0773a03 = hVar.f;
                float f = this.n;
                ((L0) interfaceC0773a03).setValue(Float.valueOf(f));
                ((L0) hVar.e).setValue(null);
                L0 l0 = (L0) hVar.i;
                com.airbnb.lottie.h hVar2 = this.o;
                l0.setValue(hVar2);
                hVar.h(this.p);
                ((L0) hVar.g).setValue(bool);
                ((L0) hVar.l).setValue(Long.MIN_VALUE);
                if (hVar2 == null) {
                    h.b(hVar, false);
                    return Unit.a;
                }
                if (Float.isInfinite(f)) {
                    hVar.h(hVar.e());
                    h.b(hVar, false);
                    hVar.g(i2);
                    return Unit.a;
                }
                h.b(hVar, true);
                int iOrdinal = this.q.ordinal();
                if (iOrdinal == 0) {
                    coroutineContext = kotlin.coroutines.n.a;
                } else {
                    if (iOrdinal != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    coroutineContext = u0.a;
                }
                c cVar = new c(this.q, E.s(getContext()), this.m, this.l, this.k, null);
                this.j = 1;
                if (E.J(coroutineContext, cVar, this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            E.o(getContext());
            h.b(hVar, false);
            return Unit.a;
        } catch (Throwable th) {
            h.b(hVar, false);
            throw th;
        }
    }
}
