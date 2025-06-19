package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ i l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(i iVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        d dVar = new d(this.l, hVar);
        dVar.k = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((QuestionSettings) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            QuestionSettings questionSettings = (QuestionSettings) this.k;
            this.j = 1;
            if (i.A(this.l, questionSettings, this) == aVar) {
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
