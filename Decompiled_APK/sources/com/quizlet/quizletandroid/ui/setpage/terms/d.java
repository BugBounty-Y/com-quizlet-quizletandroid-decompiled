package com.quizlet.quizletandroid.ui.setpage.terms;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.material.internal.q;
import com.quizlet.eventlogger.features.setpage.SetPagePerformanceLogger;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ TermListFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(TermListFragment termListFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = termListFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        d dVar = new d(this.k, hVar);
        dVar.j = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((com.quizlet.features.setpage.terms.g) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.setpage.terms.g gVar = (com.quizlet.features.setpage.terms.g) this.j;
        boolean zB = Intrinsics.b(gVar, com.quizlet.features.setpage.terms.e.a);
        TermListFragment termListFragment = this.k;
        if (zB) {
            String str = TermListFragment.H;
            q qVar = termListFragment.l;
            qVar.c = true;
            qVar.a();
        } else {
            if (!(gVar instanceof com.quizlet.features.setpage.terms.f)) {
                throw new NoWhenBranchMatchedException();
            }
            com.quizlet.features.setpage.terms.f fVar = (com.quizlet.features.setpage.terms.f) gVar;
            List list = fVar.a;
            com.quizlet.quizletandroid.ui.common.adapter.h hVar = termListFragment.D;
            if (hVar == null) {
                Intrinsics.m("termListAdapter");
                throw null;
            }
            ArrayList arrayList = hVar.c;
            arrayList.clear();
            if (list != null) {
                arrayList.addAll(list);
            }
            ArrayList arrayList2 = hVar.d;
            if (arrayList2.isEmpty()) {
                hVar.notifyDataSetChanged();
            } else {
                int size = arrayList2.size() + 1;
                hVar.notifyItemRangeChanged(size, hVar.getItemCount() - size);
            }
            SetPagePerformanceLogger setPagePerformanceLogger = termListFragment.B;
            if (setPagePerformanceLogger == null) {
                Intrinsics.m("setPagePerformanceLogger");
                throw null;
            }
            setPagePerformanceLogger.o();
            com.quizlet.quizletandroid.ui.common.adapter.h hVar2 = termListFragment.D;
            if (hVar2 == null) {
                Intrinsics.m("termListAdapter");
                throw null;
            }
            List list2 = fVar.b;
            DiagramData[] diagramDataArr = (DiagramData[]) list2.toArray(new DiagramData[0]);
            DiagramData[] diagramDataArr2 = (DiagramData[]) Arrays.copyOf(diagramDataArr, diagramDataArr.length);
            ArrayList arrayList3 = hVar2.d;
            arrayList3.clear();
            if (diagramDataArr2 != null) {
                arrayList3.addAll(Arrays.asList(diagramDataArr2));
            }
            hVar2.notifyItemRangeChanged(0, arrayList3.size() + 1);
            if (!list2.isEmpty()) {
                SetPagePerformanceLogger setPagePerformanceLogger2 = termListFragment.B;
                if (setPagePerformanceLogger2 == null) {
                    Intrinsics.m("setPagePerformanceLogger");
                    throw null;
                }
                setPagePerformanceLogger2.b(true);
            }
        }
        return Unit.a;
    }
}
