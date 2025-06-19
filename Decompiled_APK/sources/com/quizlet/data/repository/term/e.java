package com.quizlet.data.repository.term;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.p;
import kotlin.r;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes2.dex */
public final class e extends i implements Function2 {
    public int j;
    public final /* synthetic */ g k;
    public final /* synthetic */ long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(g gVar, long j, h hVar) {
        super(2, hVar);
        this.k = gVar;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new e(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((InterfaceC5002j) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            p pVar = r.b;
            com.quizlet.data.repository.set.f fVar = this.k.a;
            this.j = 1;
            if (fVar.i(this.l, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        p pVar2 = r.b;
        return Unit.a;
    }
}
