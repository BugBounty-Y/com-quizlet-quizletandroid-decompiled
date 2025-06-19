package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.Y;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.features.infra.basestudy.data.models.logging.StudyEventLogData;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class D extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ G j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(G g, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new D(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((D) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        G g = this.j;
        Y y = g.s;
        StudyEventLogData studyEventLogDataD = g.D.d();
        InterfaceC4176w0 interfaceC4176w0 = g.I;
        if (interfaceC4176w0 != null) {
            y.j(new com.quizlet.quizletandroid.ui.studymodes.testmode.models.s(studyEventLogDataD, interfaceC4176w0));
            return Unit.a;
        }
        Intrinsics.m("testMeteredEvent");
        throw null;
    }
}
