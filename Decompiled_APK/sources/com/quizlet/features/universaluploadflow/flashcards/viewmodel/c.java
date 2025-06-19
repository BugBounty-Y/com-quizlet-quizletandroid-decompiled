package com.quizlet.features.universaluploadflow.flashcards.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.r2;
import com.quizlet.features.universaluploadflow.flashcards.data.m;
import com.quizlet.features.universaluploadflow.flashcards.data.p;
import com.quizlet.generated.enums.EnumC4483g0;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public int j;
    public final /* synthetic */ e k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(e eVar, h hVar) {
        super(2, hVar);
        this.k = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new c(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        e eVar = this.k;
        if (i == 0) {
            Z.e(obj);
            p pVar = eVar.k;
            r2 r2Var = new r2(pVar != null ? pVar.c() : K.a, !eVar.B());
            this.j = 1;
            obj = eVar.c.q(eVar.i, r2Var, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        com.quizlet.features.universaluploadflow.logging.b.e(eVar.e, null, eVar.B(), null, null, EnumC4483g0.FLASHCARD_SET.a(), 13);
        eVar.h.h(new m((String) obj));
        return Unit.a;
    }
}
