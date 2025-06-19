package com.quizlet.quizletandroid.ui.studymodes.assistant.settings;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class r extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function1 k;
    public final /* synthetic */ Function0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(kotlin.coroutines.h hVar, Function0 function0, Function1 function1) {
        super(2, hVar);
        this.k = function1;
        this.l = function0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        r rVar = new r(hVar, this.l, this.k);
        rVar.j = obj;
        return rVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((r) create((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.l) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.l lVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.l) this.j;
        if (lVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.i) {
            this.k.invoke(((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.i) lVar).a);
        } else if (Intrinsics.b(lVar, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.j.a)) {
            this.l.invoke();
        } else if (!(lVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.k)) {
            throw new NoWhenBranchMatchedException();
        }
        return Unit.a;
    }
}
