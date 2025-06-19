package com.quizlet.features.flashcards.settings.ui;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.quizlet.features.flashcards.G;
import com.quizlet.features.flashcards.S;
import com.quizlet.features.flashcards.settings.m;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ S k;
    public final /* synthetic */ Function0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(S s, Function0 function0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = s;
        this.l = function0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        d dVar = new d(this.k, this.l, hVar);
        dVar.j = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((com.quizlet.features.flashcards.settings.c) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.flashcards.settings.c cVar = (com.quizlet.features.flashcards.settings.c) this.j;
        boolean z = cVar instanceof com.quizlet.features.flashcards.settings.b;
        S s = this.k;
        if (z) {
            com.quizlet.features.flashcards.settings.d updates = ((com.quizlet.features.flashcards.settings.b) cVar).a;
            s.getClass();
            Intrinsics.checkNotNullParameter(updates, "updates");
            E.A(p0.j(s), null, null, new G(s, updates, null), 3);
            this.l.invoke();
        } else {
            if (!(cVar instanceof m)) {
                throw new NoWhenBranchMatchedException();
            }
            com.quizlet.features.flashcards.settings.d updates2 = ((m) cVar).a;
            s.getClass();
            Intrinsics.checkNotNullParameter(updates2, "updates");
            E.A(p0.j(s), null, null, new G(s, updates2, null), 3);
        }
        return Unit.a;
    }
}
