package com.quizlet.features.practicetest.detail.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.practicetest.common.data.PracticeTestConfigurationData;
import com.quizlet.features.practicetest.detail.data.A;
import com.quizlet.generated.enums.EnumC4513q0;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ i k;
    public final /* synthetic */ Long l;
    public final /* synthetic */ PracticeTestConfigurationData m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(i iVar, Long l, PracticeTestConfigurationData practiceTestConfigurationData, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = iVar;
        this.l = l;
        this.m = practiceTestConfigurationData;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        i iVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.data.interactor.course.a aVar2 = iVar.d;
            EnumC4513q0 enumC4513q0 = EnumC4513q0.TEST_PREVIEW_PAGE;
            PracticeTestConfigurationData practiceTestConfigurationData = this.m;
            iVar.e.getClass();
            ArrayList arrayListK = com.google.firebase.perf.logging.b.k(practiceTestConfigurationData);
            this.j = 1;
            obj = aVar2.g(iVar.m, 1, enumC4513q0, this.l, practiceTestConfigurationData.a, arrayListK, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        iVar.k.h(new A((String) obj, iVar.m, iVar.n));
        return Unit.a;
    }
}
