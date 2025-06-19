package com.quizlet.explanations.myexplanations.viewmodel;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.quizletandroid.R;
import java.util.Collection;
import java.util.List;
import kotlin.collections.B;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class l implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ m b;

    public /* synthetic */ l(m mVar, int i) {
        this.a = i;
        this.b = mVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        com.quizlet.explanations.myexplanations.data.i iVar;
        Collection collection;
        Iterable iterable;
        switch (this.a) {
            case 0:
                List list = (List) obj;
                Intrinsics.checkNotNullParameter(list, "list");
                com.quizlet.explanations.myexplanations.data.l lVar = (com.quizlet.explanations.myexplanations.data.l) list.get(0);
                com.quizlet.explanations.myexplanations.data.l lVar2 = (com.quizlet.explanations.myexplanations.data.l) list.get(1);
                this.b.getClass();
                List<com.quizlet.explanations.myexplanations.data.l> listJ = B.j(lVar, lVar2);
                if (listJ == null || !listJ.isEmpty()) {
                    for (com.quizlet.explanations.myexplanations.data.l lVar3 : listJ) {
                        lVar3.getClass();
                        if (!(lVar3 instanceof com.quizlet.explanations.myexplanations.data.k)) {
                            if (listJ.isEmpty()) {
                                Object[] args = new Object[0];
                                Intrinsics.checkNotNullParameter(args, "args");
                                iVar = new com.quizlet.explanations.myexplanations.data.i(new com.quizlet.qutils.string.f(R.string.client_error_net_exception, C4933y.P(args)), true);
                            } else {
                                for (com.quizlet.explanations.myexplanations.data.l lVar4 : listJ) {
                                    lVar4.getClass();
                                    com.quizlet.explanations.myexplanations.data.i iVar2 = lVar4 instanceof com.quizlet.explanations.myexplanations.data.i ? (com.quizlet.explanations.myexplanations.data.i) lVar4 : null;
                                    if (iVar2 == null || !iVar2.b) {
                                        if (!listJ.isEmpty()) {
                                            for (com.quizlet.explanations.myexplanations.data.l lVar5 : listJ) {
                                                lVar5.getClass();
                                                if (!(lVar5 instanceof com.quizlet.explanations.myexplanations.data.i)) {
                                                    com.quizlet.explanations.myexplanations.data.j jVar = lVar instanceof com.quizlet.explanations.myexplanations.data.j ? (com.quizlet.explanations.myexplanations.data.j) lVar : null;
                                                    if (jVar == null || (collection = jVar.b) == null) {
                                                        collection = K.a;
                                                    }
                                                    com.quizlet.explanations.myexplanations.data.j jVar2 = lVar2 instanceof com.quizlet.explanations.myexplanations.data.j ? (com.quizlet.explanations.myexplanations.data.j) lVar2 : null;
                                                    if (jVar2 == null || (iterable = jVar2.b) == null) {
                                                        iterable = K.a;
                                                    }
                                                    return new com.quizlet.explanations.myexplanations.data.j(AbstractC3409x1.h(new com.quizlet.explanations.myexplanations.data.h("my-explanations-recently-viewed-header", R.string.recently_viewed_header_title)), AbstractC3409x1.i(CollectionsKt.n0(CollectionsKt.c0(collection, iterable), new com.google.zxing.aztec.encoder.c(9))));
                                                }
                                            }
                                        }
                                        Object[] args2 = new Object[0];
                                        Intrinsics.checkNotNullParameter(args2, "args");
                                        iVar = new com.quizlet.explanations.myexplanations.data.i(new com.quizlet.qutils.string.f(R.string.my_explanations_solutions_empty_header, C4933y.P(args2)), false);
                                    }
                                }
                                Object[] args3 = new Object[0];
                                Intrinsics.checkNotNullParameter(args3, "args");
                                iVar = new com.quizlet.explanations.myexplanations.data.i(new com.quizlet.qutils.string.f(R.string.client_error_net_exception, C4933y.P(args3)), true);
                            }
                            return iVar;
                        }
                    }
                }
                return com.quizlet.explanations.myexplanations.data.k.a;
            default:
                List list2 = (List) obj;
                Intrinsics.checkNotNullParameter(list2, "list");
                Object obj2 = list2.get(0);
                if (obj2 == null) {
                    throw new NullPointerException("null cannot be cast to non-null type com.quizlet.explanations.myexplanations.data.MyExplanationsItemsState<com.quizlet.explanations.myexplanations.data.MyExplanationsTextbookItem>");
                }
                com.quizlet.explanations.myexplanations.data.l lVar6 = (com.quizlet.explanations.myexplanations.data.l) obj2;
                Object obj3 = list2.get(1);
                if (obj3 == null) {
                    throw new NullPointerException("null cannot be cast to non-null type com.quizlet.explanations.myexplanations.data.MyExplanationsItemsState<com.quizlet.explanations.myexplanations.data.MyExplanationsQuestionItem>");
                }
                com.quizlet.explanations.myexplanations.data.l lVar7 = (com.quizlet.explanations.myexplanations.data.l) obj3;
                Object obj4 = list2.get(2);
                if (obj4 == null) {
                    throw new NullPointerException("null cannot be cast to non-null type com.quizlet.explanations.myexplanations.data.MyExplanationsItemsState<com.quizlet.explanations.myexplanations.data.MyExplanationsExerciseItem>");
                }
                m mVar = this.b;
                mVar.getClass();
                List<com.quizlet.explanations.myexplanations.data.l> listJ2 = B.j(lVar6, lVar7, (com.quizlet.explanations.myexplanations.data.l) obj4);
                if (listJ2 == null || !listJ2.isEmpty()) {
                    for (com.quizlet.explanations.myexplanations.data.l lVar8 : listJ2) {
                        lVar8.getClass();
                        if (!(lVar8 instanceof com.quizlet.explanations.myexplanations.data.k)) {
                            if (!listJ2.isEmpty()) {
                                for (com.quizlet.explanations.myexplanations.data.l lVar9 : listJ2) {
                                    lVar9.getClass();
                                    com.quizlet.explanations.myexplanations.data.i iVar3 = lVar9 instanceof com.quizlet.explanations.myexplanations.data.i ? (com.quizlet.explanations.myexplanations.data.i) lVar9 : null;
                                    if (iVar3 == null || !iVar3.b) {
                                        if (!listJ2.isEmpty()) {
                                            for (com.quizlet.explanations.myexplanations.data.l lVar10 : listJ2) {
                                                lVar10.getClass();
                                                if (!(lVar10 instanceof com.quizlet.explanations.myexplanations.data.i)) {
                                                    return new com.quizlet.explanations.myexplanations.data.d(mVar.g.ordinal());
                                                }
                                            }
                                        }
                                        Object[] args4 = new Object[0];
                                        Intrinsics.checkNotNullParameter(args4, "args");
                                        return new com.quizlet.explanations.myexplanations.data.b(new com.quizlet.qutils.string.f(R.string.my_explanations_all_empty_header, C4933y.P(args4)));
                                    }
                                }
                            }
                            return com.quizlet.explanations.myexplanations.data.c.a;
                        }
                    }
                }
                return com.quizlet.explanations.myexplanations.data.e.a;
        }
    }
}
