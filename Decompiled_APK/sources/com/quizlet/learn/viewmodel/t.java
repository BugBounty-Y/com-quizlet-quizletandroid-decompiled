package com.quizlet.learn.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.learn.data.C4546k;
import com.quizlet.learn.data.LearnRoundSummaryData;
import com.quizlet.studiablemodels.StudiableCheckpoint;
import com.quizlet.studiablemodels.StudiableTaskProgress;
import java.util.ArrayList;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ G j;
    public final /* synthetic */ StudiableCheckpoint k;
    public final /* synthetic */ boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(G g, StudiableCheckpoint studiableCheckpoint, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = g;
        this.k = studiableCheckpoint;
        this.l = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new t(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((t) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        StudiableCheckpoint studiableCheckpoint;
        boolean z;
        int i;
        C4546k c4546k;
        boolean z2;
        int i2;
        int i3;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        G g = this.j;
        StudiableTaskProgress studiableTaskProgressB = g.f.b();
        com.quizlet.features.infra.basestudy.manager.f fVar = g.Z;
        com.quizlet.data.repository.progress.b bVar = g.f;
        StudiableCheckpoint studiableCheckpoint2 = this.k;
        if (studiableTaskProgressB == null || (i2 = studiableTaskProgressB.a) == 0 || (i3 = studiableTaskProgressB.b) == 0 || i2 != i3) {
            StudyableModelData studyableModelData = fVar.l;
            List list = studiableCheckpoint2.d;
            if (list == null) {
                list = K.a;
            }
            List list2 = list;
            StudiableTaskProgress studiableTaskProgressB2 = bVar.b();
            StudiableTaskProgress studiableTaskProgressB3 = bVar.b();
            int i4 = studiableTaskProgressB3 != null ? studiableTaskProgressB3.a : 0;
            StudiableTaskProgress studiableTaskProgressB4 = bVar.b();
            int i5 = studiableTaskProgressB4 != null ? studiableTaskProgressB4.b : 0;
            if (bVar.b() != null) {
                z = true;
                studiableCheckpoint = studiableCheckpoint2;
                i = (int) ((r2.a / r2.b) * 100);
            } else {
                studiableCheckpoint = studiableCheckpoint2;
                z = true;
                i = 0;
            }
            c4546k = new C4546k(new LearnRoundSummaryData.RoundCheckpointData(studyableModelData, fVar.t, list2, studiableCheckpoint.b, studiableTaskProgressB2, i4, i5, i, g.I().s, !g.t1), studiableCheckpoint.e, false);
            z2 = z;
        } else {
            StudyableModelData studyableModelData2 = fVar.l;
            List list3 = studiableCheckpoint2.d;
            if (list3 == null) {
                list3 = K.a;
            }
            List list4 = list3;
            StudiableTaskProgress studiableTaskProgressB5 = bVar.b();
            ArrayList arrayList = fVar.n;
            c4546k = new C4546k(new LearnRoundSummaryData.TaskCompletedCheckpointData(studyableModelData2, fVar.t, list4, studiableCheckpoint2.b, studiableTaskProgressB5, arrayList != null ? arrayList.size() : 0), studiableCheckpoint2.e, this.l);
            z2 = true;
        }
        g.t1 = z2;
        g.q1.e(fVar.t, fVar.v, Integer.valueOf(fVar.q), fVar.x.C, Long.valueOf(fVar.u), Long.valueOf(fVar.m), Boolean.valueOf(fVar.k), "checkpoint", null);
        g.L.j(c4546k);
        return Unit.a;
    }
}
