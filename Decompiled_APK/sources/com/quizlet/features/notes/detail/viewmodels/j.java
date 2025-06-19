package com.quizlet.features.notes.detail.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.InterfaceC4176w0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.features.notes.detail.states.e k;
    public final /* synthetic */ v l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(com.quizlet.features.notes.detail.states.e eVar, v vVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = vVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        v vVar = this.l;
        if (i == 0) {
            Z.e(obj);
            if (this.k != null) {
                this.j = 1;
                obj = vVar.A(this);
                if (obj == aVar) {
                    return aVar;
                }
            }
            vVar.r.h(com.quizlet.features.notes.detail.events.b.a);
            return Unit.a;
        }
        if (i != 1) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        Z.e(obj);
        if (((InterfaceC4176w0) obj).a0()) {
            vVar.r.h(com.quizlet.features.notes.detail.events.b.a);
        } else {
            vVar.r.h(com.quizlet.features.notes.detail.events.o.a);
        }
        return Unit.a;
    }
}
