package com.quizlet.features.universaluploadflow.flashcards;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.universaluploadflow.flashcards.data.j;
import com.quizlet.features.universaluploadflow.flashcards.data.k;
import com.quizlet.features.universaluploadflow.flashcards.data.l;
import com.quizlet.features.universaluploadflow.flashcards.data.m;
import com.quizlet.features.universaluploadflow.flashcards.data.n;
import com.quizlet.features.universaluploadflow.flashcards.data.o;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function0 k;
    public final /* synthetic */ Function0 l;
    public final /* synthetic */ com.quizlet.assembly.compose.toasts.g m;
    public final /* synthetic */ Function0 n;
    public final /* synthetic */ Function1 o;
    public final /* synthetic */ InterfaceC0773a0 p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(Function0 function0, Function0 function02, com.quizlet.assembly.compose.toasts.g gVar, Function0 function03, Function1 function1, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = function0;
        this.l = function02;
        this.m = gVar;
        this.n = function03;
        this.o = function1;
        this.p = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        i iVar = new i(this.k, this.l, this.m, this.n, this.o, this.p, hVar);
        iVar.j = obj;
        return iVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((o) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        o oVar = (o) this.j;
        if (Intrinsics.b(oVar, com.quizlet.features.universaluploadflow.flashcards.data.i.a)) {
            this.k.invoke();
        } else if (Intrinsics.b(oVar, j.a)) {
            this.l.invoke();
        } else if (Intrinsics.b(oVar, k.a)) {
            ((L0) this.m.b).setValue(Boolean.TRUE);
        } else if (Intrinsics.b(oVar, n.a)) {
            this.p.setValue(Boolean.TRUE);
        } else if (Intrinsics.b(oVar, l.a)) {
            this.n.invoke();
        } else {
            if (!(oVar instanceof m)) {
                throw new NoWhenBranchMatchedException();
            }
            this.o.invoke(((m) oVar).a);
        }
        return Unit.a;
    }
}
