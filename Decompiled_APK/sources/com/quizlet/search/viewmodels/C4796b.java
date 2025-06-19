package com.quizlet.search.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.e0;

/* renamed from: com.quizlet.search.viewmodels.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4796b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ AbstractC4797c k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4796b(AbstractC4797c abstractC4797c, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = abstractC4797c;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4796b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4796b) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            AbstractC4797c abstractC4797c = this.k;
            C4795a c4795a = new C4795a(abstractC4797c, null);
            this.j = 1;
            if (e0.i(abstractC4797c.g, c4795a, this) == aVar) {
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
