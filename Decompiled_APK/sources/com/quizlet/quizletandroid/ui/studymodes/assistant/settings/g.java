package com.quizlet.quizletandroid.ui.studymodes.assistant.settings;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.assembly.compose.modals.x;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ x k;
    public final /* synthetic */ Function1 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(x xVar, kotlin.coroutines.h hVar, Function1 function1) {
        super(2, hVar);
        this.k = xVar;
        this.l = function1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        g gVar = new g(this.k, hVar, this.l);
        gVar.j = obj;
        return gVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.l) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.l lVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.l) this.j;
        boolean z = lVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.k;
        x xVar = this.k;
        if (z) {
            x.d(xVar);
        } else if (lVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.i) {
            this.l.invoke(((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.i) lVar).a);
            xVar.a();
        } else if (!(lVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.j)) {
            throw new NoWhenBranchMatchedException();
        }
        return Unit.a;
    }
}
