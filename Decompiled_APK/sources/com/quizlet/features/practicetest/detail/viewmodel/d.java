package com.quizlet.features.practicetest.detail.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.ads.C3;
import com.quizlet.data.exceptions.practicetests.PracticeTestsException;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.features.practicetest.common.data.PracticeTestConfigurationData;
import com.quizlet.features.practicetest.detail.data.F;
import java.util.List;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ i k;
    public final /* synthetic */ boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(i iVar, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = iVar;
        this.l = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws PracticeTestsException {
        Object objD;
        s0 s0Var;
        Object value;
        F f;
        String title;
        String createdDate;
        List pastExams;
        List questions;
        Map questionCounts;
        PracticeTestConfigurationData practiceTestConfigurationData;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        i iVar = this.k;
        boolean z = this.l;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            com.quizlet.data.repository.explanations.myexplanations.a aVar2 = iVar.j;
            objD = ((C3) aVar2.b).d(iVar.m, ((UserInfoCache) aVar2.c).getPersonId(), !z, this);
            if (objD == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objD = obj;
        }
        if (Intrinsics.b((String) objD, iVar.m)) {
            boolean z2 = !z;
            iVar.b.c(Boolean.valueOf(z2), "question_bank_private");
            do {
                s0Var = iVar.l;
                value = s0Var.getValue();
                Object value2 = s0Var.getValue();
                Intrinsics.e(value2, "null cannot be cast to non-null type com.quizlet.features.practicetest.detail.data.PracticeTestDetailUiState.Content");
                f = (F) value2;
                title = f.a;
                Intrinsics.checkNotNullParameter(title, "title");
                createdDate = f.f;
                Intrinsics.checkNotNullParameter(createdDate, "createdDate");
                pastExams = f.g;
                Intrinsics.checkNotNullParameter(pastExams, "pastExams");
                questions = f.h;
                Intrinsics.checkNotNullParameter(questions, "questions");
                questionCounts = f.i;
                Intrinsics.checkNotNullParameter(questionCounts, "questionCounts");
                practiceTestConfigurationData = f.j;
                Intrinsics.checkNotNullParameter(practiceTestConfigurationData, "practiceTestConfigurationData");
            } while (!s0Var.k(value, new F(title, f.b, f.c, f.d, f.e, createdDate, pastExams, questions, questionCounts, practiceTestConfigurationData, f.k, f.l, z2, f.n, f.o)));
        }
        return Unit.a;
    }
}
