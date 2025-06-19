package com.quizlet.features.notes.detail.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.model.NotesEventLog;
import com.quizlet.generated.enums.EnumC4465a0;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ v k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(v vVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = vVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new m(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((m) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        v vVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.data.interactor.achievements.f fVar = vVar.m;
            String strC = vVar.C();
            this.j = 1;
            if (fVar.i(strC, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        com.quizlet.features.notes.logging.f fVar2 = vVar.f;
        String strC2 = vVar.C();
        fVar2.getClass();
        NotesEventLog.Companion companion = NotesEventLog.b;
        String strA = EnumC4465a0.DELETE_NOTE_CONFIRMED.a();
        com.quizlet.features.notes.logging.c cVar = new com.quizlet.features.notes.logging.c(strC2, 21);
        EnumC4503n enumC4503n = com.quizlet.features.notes.logging.a.c;
        companion.getClass();
        fVar2.a(NotesEventLog.Companion.a(enumC4503n, strA, cVar));
        vVar.r.h(com.quizlet.features.notes.detail.events.b.a);
        return Unit.a;
    }
}
