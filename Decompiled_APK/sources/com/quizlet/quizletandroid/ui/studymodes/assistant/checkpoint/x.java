package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class x extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function0 k;
    public final /* synthetic */ Function0 l;
    public final /* synthetic */ Function0 m;
    public final /* synthetic */ Function0 n;
    public final /* synthetic */ Function0 o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public x(Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function0 function05, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = function0;
        this.l = function02;
        this.m = function03;
        this.n = function04;
        this.o = function05;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        x xVar = new x(this.k, this.l, this.m, this.n, this.o, hVar);
        xVar.j = obj;
        return xVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((x) create((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.l) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.l lVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.l) this.j;
        if (Intrinsics.b(lVar, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.g.a)) {
            this.k.invoke();
        } else if (Intrinsics.b(lVar, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.h.a)) {
            this.l.invoke();
        } else if (Intrinsics.b(lVar, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.i.a)) {
            this.m.invoke();
        } else if (Intrinsics.b(lVar, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.k.a)) {
            this.n.invoke();
        } else {
            if (!Intrinsics.b(lVar, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.j.a)) {
                throw new NoWhenBranchMatchedException();
            }
            this.o.invoke();
        }
        return Unit.a;
    }
}
