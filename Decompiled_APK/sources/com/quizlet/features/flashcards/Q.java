package com.quizlet.features.flashcards;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.Y;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3146g0;
import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class Q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ com.quizlet.features.flashcards.data.e j;
    public final /* synthetic */ S k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Q(com.quizlet.features.flashcards.data.e eVar, S s, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = eVar;
        this.k = s;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new Q(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((Q) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.flashcards.data.e eVar = this.j;
        AbstractC3146g0 abstractC3146g0 = eVar.a;
        boolean z = abstractC3146g0 instanceof com.quizlet.features.flashcards.data.b;
        S s = this.k;
        if (z) {
            com.quizlet.features.flashcards.data.b bVar = (com.quizlet.features.flashcards.data.b) abstractC3146g0;
            s.getClass();
            Object[] args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
            com.quizlet.qutils.string.f fVar = new com.quizlet.qutils.string.f(R.string.flashcards_still_learning, C4933y.P(args));
            Intrinsics.checkNotNullParameter(fVar, "<set-?>");
            bVar.h = fVar;
            Y y = s.t;
            com.quizlet.features.flashcards.data.o oVarG = s.G();
            com.quizlet.features.flashcards.engine.h hVar = s.c;
            com.quizlet.features.infra.models.flashcards.d dVarD = hVar.d();
            String str = dVarD.a.a;
            String str2 = dVarD.b.a;
            boolean z2 = dVarD.c || dVarD.d;
            y.l(com.quizlet.features.flashcards.data.o.a(oVarG, eVar.c, eVar.d, eVar.b, eVar.g, hVar.d().b() == com.quizlet.features.infra.models.flashcards.c.c, hVar.d().e, z2, eVar.f, null, bVar, 256));
            s.H();
            s.F();
        } else {
            if (!(abstractC3146g0 instanceof com.quizlet.features.flashcards.data.t)) {
                throw new NoWhenBranchMatchedException();
            }
            s.getClass();
            kotlinx.coroutines.E.A(p0.j(s), null, null, new N(s, ((com.quizlet.features.flashcards.data.t) abstractC3146g0).b, eVar.c, eVar.d, eVar.b, eVar.g, eVar.f, null), 3);
        }
        return Unit.a;
    }
}
