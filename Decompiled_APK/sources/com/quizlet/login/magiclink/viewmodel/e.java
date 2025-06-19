package com.quizlet.login.magiclink.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.W;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ g k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(g gVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        g gVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.features.flashcards.helpers.d dVar = new com.quizlet.features.flashcards.helpers.d(new com.quizlet.analytics.marketing.appsflyer.d((W) gVar.b.a, 2), 5);
            this.j = 1;
            obj = e0.p(dVar, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        String str = (String) obj;
        s0 s0Var = gVar.d;
        do {
            value = s0Var.getValue();
        } while (!s0Var.k(value, str));
        return Unit.a;
    }
}
