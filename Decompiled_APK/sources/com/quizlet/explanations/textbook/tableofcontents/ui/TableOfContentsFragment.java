package com.quizlet.explanations.textbook.tableofcontents.ui;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.lifecycle.p0;
import androidx.lifecycle.u0;
import androidx.navigation.U;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.braze.triggers.managers.h;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.appbar.CollapsingToolbarLayout;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.explanations.databinding.k;
import com.quizlet.explanations.databinding.n;
import com.quizlet.explanations.textbook.viewmodel.c;
import com.quizlet.generated.enums.y1;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.maybe.w;
import io.reactivex.rxjava3.internal.operators.single.d;
import io.reactivex.rxjava3.subjects.r;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.l;
import kotlin.u;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes2.dex */
public final class TableOfContentsFragment extends Hilt_TableOfContentsFragment<k> {
    public static final String p;
    public com.google.mlkit.common.sdkinternal.model.a j;
    public com.quizlet.qutils.image.loading.a k;
    public com.quizlet.explanations.myexplanations.ui.recyclerview.b n;
    public final e l = new e(K.a(com.quizlet.explanations.textbook.tableofcontents.viewmodel.b.class), new a(this, 0), new a(this, 2), new a(this, 1));
    public final e m = new e(K.a(c.class), new a(this, 3), new a(this, 5), new a(this, 4));
    public final u o = l.b(new com.quizlet.db.data.models.persisted.types.a(20));

    static {
        Intrinsics.checkNotNullExpressionValue("TextbookFragment", "getSimpleName(...)");
        p = "TextbookFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return p;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_table_of_contents, viewGroup, false);
        int i = R.id.appBarLayout;
        if (((AppBarLayout) AbstractC3375o2.c(R.id.appBarLayout, viewInflate)) != null) {
            i = R.id.assistant_checkpoint_toolbar;
            if (((CollapsingToolbarLayout) AbstractC3375o2.c(R.id.assistant_checkpoint_toolbar, viewInflate)) != null) {
                i = R.id.chapterList;
                RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.chapterList, viewInflate);
                if (recyclerView != null) {
                    i = R.id.headerOfTextbook;
                    View viewC = AbstractC3375o2.c(R.id.headerOfTextbook, viewInflate);
                    if (viewC != null) {
                        int i2 = R.id.textbookAuthor;
                        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.textbookAuthor, viewC);
                        if (qTextView != null) {
                            i2 = R.id.textbookCover;
                            ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.textbookCover, viewC);
                            if (imageView != null) {
                                i2 = R.id.textbookEdition;
                                QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.textbookEdition, viewC);
                                if (qTextView2 != null) {
                                    i2 = R.id.textbookIsbn;
                                    QTextView qTextView3 = (QTextView) AbstractC3375o2.c(R.id.textbookIsbn, viewC);
                                    if (qTextView3 != null) {
                                        i2 = R.id.textbookTitle;
                                        QTextView qTextView4 = (QTextView) AbstractC3375o2.c(R.id.textbookTitle, viewC);
                                        if (qTextView4 != null) {
                                            k kVar = new k((CoordinatorLayout) viewInflate, recyclerView, new n((ConstraintLayout) viewC, qTextView, imageView, qTextView2, qTextView3, qTextView4, 0));
                                            Intrinsics.checkNotNullExpressionValue(kVar, "inflate(...)");
                                            return kVar;
                                        }
                                    }
                                }
                            }
                        }
                        throw new NullPointerException("Missing required view with ID: ".concat(viewC.getResources().getResourceName(i2)));
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final c T() {
        return (c) this.m.getValue();
    }

    public final com.quizlet.explanations.textbook.tableofcontents.viewmodel.b U() {
        return (com.quizlet.explanations.textbook.tableofcontents.viewmodel.b) this.l.getValue();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        com.quizlet.explanations.textbook.tableofcontents.viewmodel.b bVarU = U();
        String isbn = requireArguments().getString("ARG_TEXTBOOK_ISBN");
        if (isbn == null) {
            throw new IllegalStateException("Missing required argument (ARG_TEXTBOOK_ISBN)");
        }
        bVarU.getClass();
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        com.quizlet.data.repository.widget.b bVar = bVarU.d;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        r stopToken = bVarU.c;
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        w wVarC = ((androidx.work.impl.model.c) bVar.c).c(stopToken, new h(23, bVar, isbn));
        androidx.work.impl.model.c cVar = bVarU.f;
        io.reactivex.rxjava3.internal.operators.single.e eVar = new io.reactivex.rxjava3.internal.operators.single.e(new d(p.o(wVarC, cVar.t(), cVar.r(), com.quizlet.explanations.textbook.tableofcontents.viewmodel.a.a), new com.quizlet.analytics.marketing.e(bVarU, 3), 1), new com.quizlet.eventlogger.e(bVarU, 3), 1);
        Intrinsics.checkNotNullExpressionValue(eVar, "doFinally(...)");
        io.reactivex.rxjava3.internal.observers.e eVarB = B7.b(eVar, new u0(18, bVarU, isbn), new U(bVarU, 23));
        Intrinsics.checkNotNullParameter(eVarB, "<this>");
        bVarU.A(eVarB);
        if (this.j != null) {
            this.n = new com.quizlet.explanations.myexplanations.ui.recyclerview.b(AbstractC4178x.h("diffUtilCallback"), 5);
        } else {
            Intrinsics.m("adapterFactory");
            throw null;
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        ((k) J()).b.setAdapter(null);
        super.onDestroyView();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        c cVarT = T();
        String studyMaterialId = requireArguments().getString("ARG_TEXTBOOK_ISBN");
        if (studyMaterialId == null) {
            throw new IllegalStateException("Missing required argument (ARG_TEXTBOOK_ISBN)");
        }
        y1 studyMaterialType = y1.TEXTBOOK;
        cVarT.getClass();
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        E.A(p0.j(cVarT), null, null, new com.quizlet.explanations.textbook.viewmodel.b(cVarT, false, studyMaterialId, studyMaterialType, null), 3);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        k kVar = (k) J();
        getContext();
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(1);
        RecyclerView recyclerView = kVar.b;
        recyclerView.setLayoutManager(linearLayoutManager);
        com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar = this.n;
        if (bVar == null) {
            Intrinsics.m("chapterAdapter");
            throw null;
        }
        recyclerView.setAdapter(bVar);
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        com.quizlet.baserecyclerview.decoration.d dVar = com.quizlet.baserecyclerview.decoration.d.a;
        recyclerView.i(new com.quizlet.baserecyclerview.decoration.e(contextRequireContext, R.dimen.ref_spacing_xsmall));
        U().h.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(4, new com.quizlet.explanations.solution.fragments.b(1, this, TableOfContentsFragment.class, "handleLoadedState", "handleLoadedState(Z)V", 0, 21)));
        U().j.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(4, new com.quizlet.explanations.solution.fragments.b(1, this, TableOfContentsFragment.class, "bindTextBook", "bindTextBook(Lcom/quizlet/explanations/textbook/data/TextbookHeaderViewState;)V", 0, 22)));
        U().k.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(4, new com.quizlet.explanations.solution.fragments.b(1, this, TableOfContentsFragment.class, "bindChapterList", "bindChapterList(Ljava/util/List;)V", 0, 23)));
        U().i.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(4, new U(this, 22)));
        U().l.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(4, new com.quizlet.explanations.solution.fragments.b(1, T(), c.class, "goToChapterMenu", "goToChapterMenu(Lcom/quizlet/data/model/TableOfContentItem;)V", 0, 24)));
        U().m.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(4, new com.quizlet.explanations.solution.fragments.b(1, T(), c.class, "onError", "onError(Lcom/quizlet/uicommon/ui/states/GeneralErrorDialogState;)V", 0, 25)));
    }
}
