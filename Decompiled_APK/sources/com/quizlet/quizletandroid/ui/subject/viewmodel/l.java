package com.quizlet.quizletandroid.ui.subject.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.generated.enums.K1;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ m k;
    public final /* synthetic */ K1 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(m mVar, K1 k1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = mVar;
        this.l = k1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new l(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((l) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        K1 k1 = this.l;
        m mVar = this.k;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            if (m.B(mVar, k1, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        mVar.getClass();
        String subjectType = k1.a();
        com.quizlet.data.interactor.achievements.f fVar = mVar.e;
        fVar.getClass();
        Intrinsics.checkNotNullParameter(subjectType, "subjectType");
        EventLoggerExt.c((EventLogger) fVar.b, new com.quizlet.features.notes.logging.c(subjectType, 24));
        return Unit.a;
    }
}
