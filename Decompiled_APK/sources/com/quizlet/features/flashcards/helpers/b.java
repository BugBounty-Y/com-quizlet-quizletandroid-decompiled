package com.quizlet.features.flashcards.helpers;

import androidx.glance.appwidget.protobuf.Z;
import com.google.protobuf.AbstractC4025t;
import com.google.protobuf.AbstractC4027v;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b extends i implements Function2 {
    public /* synthetic */ Object j;

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        b bVar = new b(2, hVar);
        bVar.j = obj;
        return bVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((com.quizlet.local.datastore.models.flashcards.d) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.local.datastore.models.flashcards.d dVar = (com.quizlet.local.datastore.models.flashcards.d) this.j;
        AbstractC4025t abstractC4025t = (AbstractC4025t) dVar.l(5);
        if (!abstractC4025t.a.equals(dVar)) {
            abstractC4025t.k();
            AbstractC4025t.l(abstractC4025t.b, dVar);
        }
        com.quizlet.local.datastore.models.flashcards.c cVar = (com.quizlet.local.datastore.models.flashcards.c) abstractC4025t;
        cVar.k();
        com.quizlet.local.datastore.models.flashcards.d.w((com.quizlet.local.datastore.models.flashcards.d) cVar.b);
        AbstractC4027v abstractC4027vH = cVar.h();
        Intrinsics.checkNotNullExpressionValue(abstractC4027vH, "build(...)");
        return abstractC4027vH;
    }
}
