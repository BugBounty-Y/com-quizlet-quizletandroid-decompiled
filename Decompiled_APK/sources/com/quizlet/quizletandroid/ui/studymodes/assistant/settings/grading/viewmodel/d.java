package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ g l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(g gVar, h hVar) {
        super(2, hVar);
        this.l = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        d dVar = new d(this.l, hVar);
        dVar.k = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((com.quizlet.features.infra.studysetting.managers.a) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            QuestionSettings questionSettingsC = ((com.quizlet.features.infra.studysetting.managers.a) this.k).c();
            this.j = 1;
            if (g.A(this.l, questionSettingsC, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
