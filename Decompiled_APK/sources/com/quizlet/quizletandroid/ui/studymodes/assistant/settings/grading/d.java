package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.e;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.f;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function0 k;
    public final /* synthetic */ Function0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(Function0 function0, Function0 function02, h hVar) {
        super(2, hVar);
        this.k = function0;
        this.l = function02;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        d dVar = new d(this.k, this.l, hVar);
        dVar.j = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((f) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        f fVar = (f) this.j;
        if (Intrinsics.b(fVar, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.d.a)) {
            this.k.invoke();
        } else {
            if (!(fVar instanceof e)) {
                throw new NoWhenBranchMatchedException();
            }
            this.l.invoke();
        }
        return Unit.a;
    }
}
