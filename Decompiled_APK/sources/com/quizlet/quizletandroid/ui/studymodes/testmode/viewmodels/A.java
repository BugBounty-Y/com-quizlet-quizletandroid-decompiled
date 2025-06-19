package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.Y;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class A extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ G k;
    public final /* synthetic */ List l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(G g, List list, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = g;
        this.l = list;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new A(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((A) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objA;
        String title;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        G g = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.features.infra.basestudy.usecase.b bVar = g.n;
            com.quizlet.features.infra.basestudy.manager.f fVar = g.D;
            StudyableModelData studyableModelData = fVar.l;
            this.j = 1;
            objA = bVar.a(studyableModelData, fVar.m, true, this);
            if (objA == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objA = obj;
        }
        com.quizlet.features.infra.basestudy.usecase.e eVar = (com.quizlet.features.infra.basestudy.usecase.e) objA;
        Y y = g.A;
        com.quizlet.features.infra.basestudy.manager.f fVar2 = g.D;
        StudyableModelData studyableModelData2 = fVar2.l;
        DBStudySet dBStudySetE = fVar2.e();
        if (dBStudySetE == null || (title = dBStudySetE.getTitle()) == null) {
            title = "";
        }
        y.j(new com.quizlet.quizletandroid.ui.studymodes.testmode.models.d(studyableModelData2, fVar2.m, title, g.D(), eVar.a, this.l, eVar.b));
        return Unit.a;
    }
}
