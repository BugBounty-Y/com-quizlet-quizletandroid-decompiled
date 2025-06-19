package com.quizlet.features.setpage.termlist.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.work.impl.model.v;
import com.facebook.z;
import com.quizlet.features.setpage.termlist.data.n;
import com.quizlet.features.setpage.termlist.data.p;
import com.quizlet.generated.enums.G1;
import com.quizlet.infra.legacysyncengine.datasources.w;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ j j;
    public final /* synthetic */ boolean k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(j jVar, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = jVar;
        this.k = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        s0 s0Var;
        Object value;
        p pVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        j jVar = this.j;
        v vVar = jVar.f;
        vVar.getClass();
        G1 g1 = G1.SET;
        z zVar = (z) vVar.b;
        long j = jVar.g;
        boolean z = this.k;
        zVar.c(j, g1, z);
        com.quizlet.data.repository.explanations.textbook.a aVar2 = (com.quizlet.data.repository.explanations.textbook.a) vVar.c;
        w wVarA = ((com.quizlet.infra.legacysyncengine.datasources.factory.b) aVar2.a).a(j);
        wVarA.e((com.quizlet.infra.legacysyncengine.datasources.factory.a) aVar2.d);
        if (wVarA.f != z) {
            wVarA.f = z;
            wVarA.c();
        }
        do {
            s0Var = jVar.h;
            value = s0Var.getValue();
            pVar = (p) value;
            Intrinsics.e(pVar, "null cannot be cast to non-null type com.quizlet.features.setpage.termlist.data.TermsViewState.Content");
        } while (!s0Var.k(value, n.a((n) pVar, null, null, null, this.k, 15)));
        return Unit.a;
    }
}
