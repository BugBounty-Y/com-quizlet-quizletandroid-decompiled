package com.quizlet.explanations.myexplanations.ui.fragments;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import androidx.compose.foundation.text.z0;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.C1370i;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.onetrust.otpublishers.headless.Internal.Helper.h;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.explanations.databinding.i;
import com.quizlet.explanations.myexplanations.data.d;
import com.quizlet.explanations.myexplanations.data.e;
import com.quizlet.explanations.myexplanations.data.g;
import com.quizlet.explanations.myexplanations.data.j;
import com.quizlet.explanations.myexplanations.data.l;
import com.quizlet.explanations.myexplanations.data.p;
import com.quizlet.explanations.myexplanations.data.q;
import com.quizlet.explanations.myexplanations.ui.recyclerview.f;
import com.quizlet.explanations.myexplanations.viewmodel.m;
import com.quizlet.partskit.widgets.QProgressBar;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.C;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class AllExplanationsPageFragment extends Hilt_AllExplanationsPageFragment {
    public static final String w;
    public assistantMode.utils.studiableMetadata.b k;
    public h l;
    public com.quizlet.shared.usecase.folderstudymaterials.b m;
    public com.quizlet.shared.usecase.folderstudymaterials.a n;
    public com.google.mlkit.common.sdkinternal.model.a o;
    public C1370i p;
    public com.quizlet.explanations.myexplanations.ui.recyclerview.b q;
    public com.quizlet.explanations.myexplanations.ui.recyclerview.b r;
    public com.quizlet.explanations.myexplanations.ui.recyclerview.b s;
    public com.quizlet.explanations.myexplanations.ui.recyclerview.b t;
    public com.quizlet.explanations.myexplanations.ui.recyclerview.b u;
    public com.quizlet.explanations.myexplanations.ui.recyclerview.b v;

    static {
        Intrinsics.checkNotNullExpressionValue("AllExplanationsPageFragment", "getSimpleName(...)");
        w = "AllExplanationsPageFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return w;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (this.k == null) {
            Intrinsics.m("concatAdapterFactory");
            throw null;
        }
        this.p = new C1370i(new AbstractC1361d0[0]);
        if (this.l == null) {
            Intrinsics.m("headerAdapterFactory");
            throw null;
        }
        com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar = new com.quizlet.explanations.myexplanations.ui.recyclerview.b(AbstractC4178x.h("diffUtilCallback"), 1);
        this.q = bVar;
        C1370i c1370i = this.p;
        if (c1370i == null) {
            Intrinsics.m("mainAdapter");
            throw null;
        }
        c1370i.d(bVar);
        if (this.m == null) {
            Intrinsics.m("textbookAdapterFactory");
            throw null;
        }
        com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar2 = new com.quizlet.explanations.myexplanations.ui.recyclerview.b(AbstractC4178x.h("diffUtilCallback"), 3);
        this.r = bVar2;
        C1370i c1370i2 = this.p;
        if (c1370i2 == null) {
            Intrinsics.m("mainAdapter");
            throw null;
        }
        c1370i2.d(bVar2);
        if (this.l == null) {
            Intrinsics.m("headerAdapterFactory");
            throw null;
        }
        com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar3 = new com.quizlet.explanations.myexplanations.ui.recyclerview.b(AbstractC4178x.h("diffUtilCallback"), 1);
        this.s = bVar3;
        C1370i c1370i3 = this.p;
        if (c1370i3 == null) {
            Intrinsics.m("mainAdapter");
            throw null;
        }
        c1370i3.d(bVar3);
        if (this.n == null) {
            Intrinsics.m("questionAdapterFactory");
            throw null;
        }
        com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar4 = new com.quizlet.explanations.myexplanations.ui.recyclerview.b(AbstractC4178x.h("diffUtilCallback"), 2);
        this.t = bVar4;
        C1370i c1370i4 = this.p;
        if (c1370i4 == null) {
            Intrinsics.m("mainAdapter");
            throw null;
        }
        c1370i4.d(bVar4);
        if (this.l == null) {
            Intrinsics.m("headerAdapterFactory");
            throw null;
        }
        com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar5 = new com.quizlet.explanations.myexplanations.ui.recyclerview.b(AbstractC4178x.h("diffUtilCallback"), 1);
        this.u = bVar5;
        C1370i c1370i5 = this.p;
        if (c1370i5 == null) {
            Intrinsics.m("mainAdapter");
            throw null;
        }
        c1370i5.d(bVar5);
        if (this.o == null) {
            Intrinsics.m("exerciseAdapterFactory");
            throw null;
        }
        com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar6 = new com.quizlet.explanations.myexplanations.ui.recyclerview.b(AbstractC4178x.h("diffUtilCallback"), 0);
        this.v = bVar6;
        C1370i c1370i6 = this.p;
        if (c1370i6 != null) {
            c1370i6.d(bVar6);
        } else {
            Intrinsics.m("mainAdapter");
            throw null;
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        final int i = 1;
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        final int i2 = 3;
        ((m) S()).p.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(1, new Function1(this) { // from class: com.quizlet.explanations.myexplanations.ui.fragments.a
            public final /* synthetic */ AllExplanationsPageFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                AllExplanationsPageFragment allExplanationsPageFragment = this.b;
                switch (i2) {
                    case 0:
                        l lVar = (l) obj;
                        String str = AllExplanationsPageFragment.w;
                        if (lVar instanceof j) {
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar = allExplanationsPageFragment.u;
                            if (bVar == null) {
                                Intrinsics.m("exerciseHeaderAdapter");
                                throw null;
                            }
                            j jVar = (j) lVar;
                            bVar.f(jVar.a);
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar2 = allExplanationsPageFragment.v;
                            if (bVar2 == null) {
                                Intrinsics.m("exerciseItemsAdapter");
                                throw null;
                            }
                            kotlinx.collections.immutable.b bVar3 = jVar.b;
                            ArrayList arrayList = new ArrayList(C.q(bVar3, 10));
                            Iterator<E> it2 = bVar3.iterator();
                            while (it2.hasNext()) {
                                arrayList.add(new com.quizlet.explanations.myexplanations.ui.recyclerview.a((g) it2.next(), new z0(1, allExplanationsPageFragment.S(), com.quizlet.explanations.myexplanations.viewmodel.a.class, "onExerciseClick", "onExerciseClick(Lcom/quizlet/explanations/myexplanations/data/MyExplanationsExerciseItem;)V", 0, 12)));
                            }
                            bVar2.f(arrayList);
                        }
                        return Unit.a;
                    case 1:
                        l lVar2 = (l) obj;
                        String str2 = AllExplanationsPageFragment.w;
                        if (lVar2 instanceof j) {
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar4 = allExplanationsPageFragment.q;
                            if (bVar4 == null) {
                                Intrinsics.m("textbookHeaderAdapter");
                                throw null;
                            }
                            j jVar2 = (j) lVar2;
                            bVar4.f(jVar2.a);
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar5 = allExplanationsPageFragment.r;
                            if (bVar5 == null) {
                                Intrinsics.m("textbookItemsAdapter");
                                throw null;
                            }
                            kotlinx.collections.immutable.b bVar6 = jVar2.b;
                            ArrayList arrayList2 = new ArrayList(C.q(bVar6, 10));
                            Iterator<E> it3 = bVar6.iterator();
                            while (it3.hasNext()) {
                                arrayList2.add(new com.quizlet.explanations.myexplanations.ui.recyclerview.h((q) it3.next(), new z0(1, allExplanationsPageFragment.S(), com.quizlet.explanations.myexplanations.viewmodel.a.class, "onTextbookClick", "onTextbookClick(Lcom/quizlet/explanations/myexplanations/data/MyExplanationsTextbookItem;)V", 0, 14)));
                            }
                            bVar5.f(arrayList2);
                        }
                        return Unit.a;
                    case 2:
                        l lVar3 = (l) obj;
                        String str3 = AllExplanationsPageFragment.w;
                        if (lVar3 instanceof j) {
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar7 = allExplanationsPageFragment.s;
                            if (bVar7 == null) {
                                Intrinsics.m("questionHeaderAdapter");
                                throw null;
                            }
                            j jVar3 = (j) lVar3;
                            bVar7.f(jVar3.a);
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar8 = allExplanationsPageFragment.t;
                            if (bVar8 == null) {
                                Intrinsics.m("questionItemsAdapter");
                                throw null;
                            }
                            kotlinx.collections.immutable.b bVar9 = jVar3.b;
                            ArrayList arrayList3 = new ArrayList(C.q(bVar9, 10));
                            Iterator<E> it4 = bVar9.iterator();
                            while (it4.hasNext()) {
                                arrayList3.add(new f((p) it4.next(), new z0(1, allExplanationsPageFragment.S(), com.quizlet.explanations.myexplanations.viewmodel.a.class, "onQuestionClick", "onQuestionClick(Lcom/quizlet/explanations/myexplanations/data/MyExplanationsQuestionItem;)V", 0, 13)));
                            }
                            bVar8.f(arrayList3);
                        }
                        return Unit.a;
                    default:
                        com.quizlet.explanations.myexplanations.data.f fVar = (com.quizlet.explanations.myexplanations.data.f) obj;
                        String str4 = AllExplanationsPageFragment.w;
                        if (fVar instanceof com.quizlet.explanations.myexplanations.data.b) {
                            com.quizlet.qutils.string.f emptyHeader = ((com.quizlet.explanations.myexplanations.data.b) fVar).a;
                            Intrinsics.checkNotNullParameter(emptyHeader, "emptyHeader");
                            QProgressBar progressBar = ((i) allExplanationsPageFragment.J()).c;
                            Intrinsics.checkNotNullExpressionValue(progressBar, "progressBar");
                            progressBar.setVisibility(8);
                            allExplanationsPageFragment.R().setVisibility(8);
                            allExplanationsPageFragment.Q().setVisibility(0);
                            QTextView qTextViewQ = allExplanationsPageFragment.Q();
                            Context contextRequireContext = allExplanationsPageFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                            qTextViewQ.setText(AbstractC3053s1.e(emptyHeader, contextRequireContext));
                        } else if (fVar instanceof d) {
                            QProgressBar progressBar2 = ((i) allExplanationsPageFragment.J()).c;
                            Intrinsics.checkNotNullExpressionValue(progressBar2, "progressBar");
                            progressBar2.setVisibility(8);
                            allExplanationsPageFragment.R().setVisibility(0);
                            allExplanationsPageFragment.Q().setVisibility(8);
                        } else if (fVar instanceof e) {
                            QProgressBar progressBar3 = ((i) allExplanationsPageFragment.J()).c;
                            Intrinsics.checkNotNullExpressionValue(progressBar3, "progressBar");
                            progressBar3.setVisibility(0);
                            allExplanationsPageFragment.R().setVisibility(8);
                            allExplanationsPageFragment.Q().setVisibility(8);
                        } else if (!(fVar instanceof com.quizlet.explanations.myexplanations.data.c)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        return Unit.a;
                }
            }
        }));
        ((m) S()).k.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(1, new Function1(this) { // from class: com.quizlet.explanations.myexplanations.ui.fragments.a
            public final /* synthetic */ AllExplanationsPageFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                AllExplanationsPageFragment allExplanationsPageFragment = this.b;
                switch (i) {
                    case 0:
                        l lVar = (l) obj;
                        String str = AllExplanationsPageFragment.w;
                        if (lVar instanceof j) {
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar = allExplanationsPageFragment.u;
                            if (bVar == null) {
                                Intrinsics.m("exerciseHeaderAdapter");
                                throw null;
                            }
                            j jVar = (j) lVar;
                            bVar.f(jVar.a);
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar2 = allExplanationsPageFragment.v;
                            if (bVar2 == null) {
                                Intrinsics.m("exerciseItemsAdapter");
                                throw null;
                            }
                            kotlinx.collections.immutable.b bVar3 = jVar.b;
                            ArrayList arrayList = new ArrayList(C.q(bVar3, 10));
                            Iterator<E> it2 = bVar3.iterator();
                            while (it2.hasNext()) {
                                arrayList.add(new com.quizlet.explanations.myexplanations.ui.recyclerview.a((g) it2.next(), new z0(1, allExplanationsPageFragment.S(), com.quizlet.explanations.myexplanations.viewmodel.a.class, "onExerciseClick", "onExerciseClick(Lcom/quizlet/explanations/myexplanations/data/MyExplanationsExerciseItem;)V", 0, 12)));
                            }
                            bVar2.f(arrayList);
                        }
                        return Unit.a;
                    case 1:
                        l lVar2 = (l) obj;
                        String str2 = AllExplanationsPageFragment.w;
                        if (lVar2 instanceof j) {
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar4 = allExplanationsPageFragment.q;
                            if (bVar4 == null) {
                                Intrinsics.m("textbookHeaderAdapter");
                                throw null;
                            }
                            j jVar2 = (j) lVar2;
                            bVar4.f(jVar2.a);
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar5 = allExplanationsPageFragment.r;
                            if (bVar5 == null) {
                                Intrinsics.m("textbookItemsAdapter");
                                throw null;
                            }
                            kotlinx.collections.immutable.b bVar6 = jVar2.b;
                            ArrayList arrayList2 = new ArrayList(C.q(bVar6, 10));
                            Iterator<E> it3 = bVar6.iterator();
                            while (it3.hasNext()) {
                                arrayList2.add(new com.quizlet.explanations.myexplanations.ui.recyclerview.h((q) it3.next(), new z0(1, allExplanationsPageFragment.S(), com.quizlet.explanations.myexplanations.viewmodel.a.class, "onTextbookClick", "onTextbookClick(Lcom/quizlet/explanations/myexplanations/data/MyExplanationsTextbookItem;)V", 0, 14)));
                            }
                            bVar5.f(arrayList2);
                        }
                        return Unit.a;
                    case 2:
                        l lVar3 = (l) obj;
                        String str3 = AllExplanationsPageFragment.w;
                        if (lVar3 instanceof j) {
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar7 = allExplanationsPageFragment.s;
                            if (bVar7 == null) {
                                Intrinsics.m("questionHeaderAdapter");
                                throw null;
                            }
                            j jVar3 = (j) lVar3;
                            bVar7.f(jVar3.a);
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar8 = allExplanationsPageFragment.t;
                            if (bVar8 == null) {
                                Intrinsics.m("questionItemsAdapter");
                                throw null;
                            }
                            kotlinx.collections.immutable.b bVar9 = jVar3.b;
                            ArrayList arrayList3 = new ArrayList(C.q(bVar9, 10));
                            Iterator<E> it4 = bVar9.iterator();
                            while (it4.hasNext()) {
                                arrayList3.add(new f((p) it4.next(), new z0(1, allExplanationsPageFragment.S(), com.quizlet.explanations.myexplanations.viewmodel.a.class, "onQuestionClick", "onQuestionClick(Lcom/quizlet/explanations/myexplanations/data/MyExplanationsQuestionItem;)V", 0, 13)));
                            }
                            bVar8.f(arrayList3);
                        }
                        return Unit.a;
                    default:
                        com.quizlet.explanations.myexplanations.data.f fVar = (com.quizlet.explanations.myexplanations.data.f) obj;
                        String str4 = AllExplanationsPageFragment.w;
                        if (fVar instanceof com.quizlet.explanations.myexplanations.data.b) {
                            com.quizlet.qutils.string.f emptyHeader = ((com.quizlet.explanations.myexplanations.data.b) fVar).a;
                            Intrinsics.checkNotNullParameter(emptyHeader, "emptyHeader");
                            QProgressBar progressBar = ((i) allExplanationsPageFragment.J()).c;
                            Intrinsics.checkNotNullExpressionValue(progressBar, "progressBar");
                            progressBar.setVisibility(8);
                            allExplanationsPageFragment.R().setVisibility(8);
                            allExplanationsPageFragment.Q().setVisibility(0);
                            QTextView qTextViewQ = allExplanationsPageFragment.Q();
                            Context contextRequireContext = allExplanationsPageFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                            qTextViewQ.setText(AbstractC3053s1.e(emptyHeader, contextRequireContext));
                        } else if (fVar instanceof d) {
                            QProgressBar progressBar2 = ((i) allExplanationsPageFragment.J()).c;
                            Intrinsics.checkNotNullExpressionValue(progressBar2, "progressBar");
                            progressBar2.setVisibility(8);
                            allExplanationsPageFragment.R().setVisibility(0);
                            allExplanationsPageFragment.Q().setVisibility(8);
                        } else if (fVar instanceof e) {
                            QProgressBar progressBar3 = ((i) allExplanationsPageFragment.J()).c;
                            Intrinsics.checkNotNullExpressionValue(progressBar3, "progressBar");
                            progressBar3.setVisibility(0);
                            allExplanationsPageFragment.R().setVisibility(8);
                            allExplanationsPageFragment.Q().setVisibility(8);
                        } else if (!(fVar instanceof com.quizlet.explanations.myexplanations.data.c)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        return Unit.a;
                }
            }
        }));
        final int i3 = 2;
        ((m) S()).m.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(1, new Function1(this) { // from class: com.quizlet.explanations.myexplanations.ui.fragments.a
            public final /* synthetic */ AllExplanationsPageFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                AllExplanationsPageFragment allExplanationsPageFragment = this.b;
                switch (i3) {
                    case 0:
                        l lVar = (l) obj;
                        String str = AllExplanationsPageFragment.w;
                        if (lVar instanceof j) {
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar = allExplanationsPageFragment.u;
                            if (bVar == null) {
                                Intrinsics.m("exerciseHeaderAdapter");
                                throw null;
                            }
                            j jVar = (j) lVar;
                            bVar.f(jVar.a);
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar2 = allExplanationsPageFragment.v;
                            if (bVar2 == null) {
                                Intrinsics.m("exerciseItemsAdapter");
                                throw null;
                            }
                            kotlinx.collections.immutable.b bVar3 = jVar.b;
                            ArrayList arrayList = new ArrayList(C.q(bVar3, 10));
                            Iterator<E> it2 = bVar3.iterator();
                            while (it2.hasNext()) {
                                arrayList.add(new com.quizlet.explanations.myexplanations.ui.recyclerview.a((g) it2.next(), new z0(1, allExplanationsPageFragment.S(), com.quizlet.explanations.myexplanations.viewmodel.a.class, "onExerciseClick", "onExerciseClick(Lcom/quizlet/explanations/myexplanations/data/MyExplanationsExerciseItem;)V", 0, 12)));
                            }
                            bVar2.f(arrayList);
                        }
                        return Unit.a;
                    case 1:
                        l lVar2 = (l) obj;
                        String str2 = AllExplanationsPageFragment.w;
                        if (lVar2 instanceof j) {
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar4 = allExplanationsPageFragment.q;
                            if (bVar4 == null) {
                                Intrinsics.m("textbookHeaderAdapter");
                                throw null;
                            }
                            j jVar2 = (j) lVar2;
                            bVar4.f(jVar2.a);
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar5 = allExplanationsPageFragment.r;
                            if (bVar5 == null) {
                                Intrinsics.m("textbookItemsAdapter");
                                throw null;
                            }
                            kotlinx.collections.immutable.b bVar6 = jVar2.b;
                            ArrayList arrayList2 = new ArrayList(C.q(bVar6, 10));
                            Iterator<E> it3 = bVar6.iterator();
                            while (it3.hasNext()) {
                                arrayList2.add(new com.quizlet.explanations.myexplanations.ui.recyclerview.h((q) it3.next(), new z0(1, allExplanationsPageFragment.S(), com.quizlet.explanations.myexplanations.viewmodel.a.class, "onTextbookClick", "onTextbookClick(Lcom/quizlet/explanations/myexplanations/data/MyExplanationsTextbookItem;)V", 0, 14)));
                            }
                            bVar5.f(arrayList2);
                        }
                        return Unit.a;
                    case 2:
                        l lVar3 = (l) obj;
                        String str3 = AllExplanationsPageFragment.w;
                        if (lVar3 instanceof j) {
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar7 = allExplanationsPageFragment.s;
                            if (bVar7 == null) {
                                Intrinsics.m("questionHeaderAdapter");
                                throw null;
                            }
                            j jVar3 = (j) lVar3;
                            bVar7.f(jVar3.a);
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar8 = allExplanationsPageFragment.t;
                            if (bVar8 == null) {
                                Intrinsics.m("questionItemsAdapter");
                                throw null;
                            }
                            kotlinx.collections.immutable.b bVar9 = jVar3.b;
                            ArrayList arrayList3 = new ArrayList(C.q(bVar9, 10));
                            Iterator<E> it4 = bVar9.iterator();
                            while (it4.hasNext()) {
                                arrayList3.add(new f((p) it4.next(), new z0(1, allExplanationsPageFragment.S(), com.quizlet.explanations.myexplanations.viewmodel.a.class, "onQuestionClick", "onQuestionClick(Lcom/quizlet/explanations/myexplanations/data/MyExplanationsQuestionItem;)V", 0, 13)));
                            }
                            bVar8.f(arrayList3);
                        }
                        return Unit.a;
                    default:
                        com.quizlet.explanations.myexplanations.data.f fVar = (com.quizlet.explanations.myexplanations.data.f) obj;
                        String str4 = AllExplanationsPageFragment.w;
                        if (fVar instanceof com.quizlet.explanations.myexplanations.data.b) {
                            com.quizlet.qutils.string.f emptyHeader = ((com.quizlet.explanations.myexplanations.data.b) fVar).a;
                            Intrinsics.checkNotNullParameter(emptyHeader, "emptyHeader");
                            QProgressBar progressBar = ((i) allExplanationsPageFragment.J()).c;
                            Intrinsics.checkNotNullExpressionValue(progressBar, "progressBar");
                            progressBar.setVisibility(8);
                            allExplanationsPageFragment.R().setVisibility(8);
                            allExplanationsPageFragment.Q().setVisibility(0);
                            QTextView qTextViewQ = allExplanationsPageFragment.Q();
                            Context contextRequireContext = allExplanationsPageFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                            qTextViewQ.setText(AbstractC3053s1.e(emptyHeader, contextRequireContext));
                        } else if (fVar instanceof d) {
                            QProgressBar progressBar2 = ((i) allExplanationsPageFragment.J()).c;
                            Intrinsics.checkNotNullExpressionValue(progressBar2, "progressBar");
                            progressBar2.setVisibility(8);
                            allExplanationsPageFragment.R().setVisibility(0);
                            allExplanationsPageFragment.Q().setVisibility(8);
                        } else if (fVar instanceof e) {
                            QProgressBar progressBar3 = ((i) allExplanationsPageFragment.J()).c;
                            Intrinsics.checkNotNullExpressionValue(progressBar3, "progressBar");
                            progressBar3.setVisibility(0);
                            allExplanationsPageFragment.R().setVisibility(8);
                            allExplanationsPageFragment.Q().setVisibility(8);
                        } else if (!(fVar instanceof com.quizlet.explanations.myexplanations.data.c)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        return Unit.a;
                }
            }
        }));
        final int i4 = 0;
        ((m) S()).o.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(1, new Function1(this) { // from class: com.quizlet.explanations.myexplanations.ui.fragments.a
            public final /* synthetic */ AllExplanationsPageFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                AllExplanationsPageFragment allExplanationsPageFragment = this.b;
                switch (i4) {
                    case 0:
                        l lVar = (l) obj;
                        String str = AllExplanationsPageFragment.w;
                        if (lVar instanceof j) {
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar = allExplanationsPageFragment.u;
                            if (bVar == null) {
                                Intrinsics.m("exerciseHeaderAdapter");
                                throw null;
                            }
                            j jVar = (j) lVar;
                            bVar.f(jVar.a);
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar2 = allExplanationsPageFragment.v;
                            if (bVar2 == null) {
                                Intrinsics.m("exerciseItemsAdapter");
                                throw null;
                            }
                            kotlinx.collections.immutable.b bVar3 = jVar.b;
                            ArrayList arrayList = new ArrayList(C.q(bVar3, 10));
                            Iterator<E> it2 = bVar3.iterator();
                            while (it2.hasNext()) {
                                arrayList.add(new com.quizlet.explanations.myexplanations.ui.recyclerview.a((g) it2.next(), new z0(1, allExplanationsPageFragment.S(), com.quizlet.explanations.myexplanations.viewmodel.a.class, "onExerciseClick", "onExerciseClick(Lcom/quizlet/explanations/myexplanations/data/MyExplanationsExerciseItem;)V", 0, 12)));
                            }
                            bVar2.f(arrayList);
                        }
                        return Unit.a;
                    case 1:
                        l lVar2 = (l) obj;
                        String str2 = AllExplanationsPageFragment.w;
                        if (lVar2 instanceof j) {
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar4 = allExplanationsPageFragment.q;
                            if (bVar4 == null) {
                                Intrinsics.m("textbookHeaderAdapter");
                                throw null;
                            }
                            j jVar2 = (j) lVar2;
                            bVar4.f(jVar2.a);
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar5 = allExplanationsPageFragment.r;
                            if (bVar5 == null) {
                                Intrinsics.m("textbookItemsAdapter");
                                throw null;
                            }
                            kotlinx.collections.immutable.b bVar6 = jVar2.b;
                            ArrayList arrayList2 = new ArrayList(C.q(bVar6, 10));
                            Iterator<E> it3 = bVar6.iterator();
                            while (it3.hasNext()) {
                                arrayList2.add(new com.quizlet.explanations.myexplanations.ui.recyclerview.h((q) it3.next(), new z0(1, allExplanationsPageFragment.S(), com.quizlet.explanations.myexplanations.viewmodel.a.class, "onTextbookClick", "onTextbookClick(Lcom/quizlet/explanations/myexplanations/data/MyExplanationsTextbookItem;)V", 0, 14)));
                            }
                            bVar5.f(arrayList2);
                        }
                        return Unit.a;
                    case 2:
                        l lVar3 = (l) obj;
                        String str3 = AllExplanationsPageFragment.w;
                        if (lVar3 instanceof j) {
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar7 = allExplanationsPageFragment.s;
                            if (bVar7 == null) {
                                Intrinsics.m("questionHeaderAdapter");
                                throw null;
                            }
                            j jVar3 = (j) lVar3;
                            bVar7.f(jVar3.a);
                            com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar8 = allExplanationsPageFragment.t;
                            if (bVar8 == null) {
                                Intrinsics.m("questionItemsAdapter");
                                throw null;
                            }
                            kotlinx.collections.immutable.b bVar9 = jVar3.b;
                            ArrayList arrayList3 = new ArrayList(C.q(bVar9, 10));
                            Iterator<E> it4 = bVar9.iterator();
                            while (it4.hasNext()) {
                                arrayList3.add(new f((p) it4.next(), new z0(1, allExplanationsPageFragment.S(), com.quizlet.explanations.myexplanations.viewmodel.a.class, "onQuestionClick", "onQuestionClick(Lcom/quizlet/explanations/myexplanations/data/MyExplanationsQuestionItem;)V", 0, 13)));
                            }
                            bVar8.f(arrayList3);
                        }
                        return Unit.a;
                    default:
                        com.quizlet.explanations.myexplanations.data.f fVar = (com.quizlet.explanations.myexplanations.data.f) obj;
                        String str4 = AllExplanationsPageFragment.w;
                        if (fVar instanceof com.quizlet.explanations.myexplanations.data.b) {
                            com.quizlet.qutils.string.f emptyHeader = ((com.quizlet.explanations.myexplanations.data.b) fVar).a;
                            Intrinsics.checkNotNullParameter(emptyHeader, "emptyHeader");
                            QProgressBar progressBar = ((i) allExplanationsPageFragment.J()).c;
                            Intrinsics.checkNotNullExpressionValue(progressBar, "progressBar");
                            progressBar.setVisibility(8);
                            allExplanationsPageFragment.R().setVisibility(8);
                            allExplanationsPageFragment.Q().setVisibility(0);
                            QTextView qTextViewQ = allExplanationsPageFragment.Q();
                            Context contextRequireContext = allExplanationsPageFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                            qTextViewQ.setText(AbstractC3053s1.e(emptyHeader, contextRequireContext));
                        } else if (fVar instanceof d) {
                            QProgressBar progressBar2 = ((i) allExplanationsPageFragment.J()).c;
                            Intrinsics.checkNotNullExpressionValue(progressBar2, "progressBar");
                            progressBar2.setVisibility(8);
                            allExplanationsPageFragment.R().setVisibility(0);
                            allExplanationsPageFragment.Q().setVisibility(8);
                        } else if (fVar instanceof e) {
                            QProgressBar progressBar3 = ((i) allExplanationsPageFragment.J()).c;
                            Intrinsics.checkNotNullExpressionValue(progressBar3, "progressBar");
                            progressBar3.setVisibility(0);
                            allExplanationsPageFragment.R().setVisibility(8);
                            allExplanationsPageFragment.Q().setVisibility(8);
                        } else if (!(fVar instanceof com.quizlet.explanations.myexplanations.data.c)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        return Unit.a;
                }
            }
        }));
        C1370i recyclerViewAdapter = this.p;
        if (recyclerViewAdapter == null) {
            Intrinsics.m("mainAdapter");
            throw null;
        }
        Intrinsics.checkNotNullParameter(recyclerViewAdapter, "recyclerViewAdapter");
        RecyclerView recyclerViewR = R();
        recyclerViewR.setAdapter(recyclerViewAdapter);
        requireContext();
        recyclerViewR.setLayoutManager(new LinearLayoutManager(1));
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        com.quizlet.baserecyclerview.decoration.d dVar = com.quizlet.baserecyclerview.decoration.d.a;
        recyclerViewR.i(new com.quizlet.baserecyclerview.decoration.e(contextRequireContext, R.dimen.ref_spacing_xsmall));
    }
}
