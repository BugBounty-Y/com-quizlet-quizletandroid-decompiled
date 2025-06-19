package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.StudySet;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ s k;
    public final /* synthetic */ long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(s sVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = sVar;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        i iVar = new i(this.k, this.l, hVar);
        iVar.j = obj;
        return iVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((StudySet) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        StudySet studySet = (StudySet) this.j;
        boolean zD = this.k.c.d(this.l);
        Intrinsics.checkNotNullParameter(studySet, "studySet");
        return new com.quizlet.features.infra.basestudy.data.models.r(1, studySet.x, new StudyableModelData.StudySet(studySet.a), studySet.h, studySet.t, zD);
    }
}
