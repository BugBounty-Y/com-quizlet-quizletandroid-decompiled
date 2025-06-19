package com.quizlet.explanations.textbook.ui;

import android.os.Bundle;
import androidx.compose.ui.layout.V;
import androidx.compose.ui.layout.W;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1132f0;
import androidx.navigation.compose.v;
import com.quizlet.explanations.textbook.chaptermenu.ui.ChapterMenuFragment;
import com.quizlet.explanations.textbook.data.h;
import com.quizlet.explanations.textbook.data.i;
import com.quizlet.explanations.textbook.data.j;
import com.quizlet.explanations.textbook.data.m;
import com.quizlet.explanations.textbook.data.n;
import com.quizlet.explanations.textbook.data.o;
import com.quizlet.explanations.textbook.data.p;
import com.quizlet.explanations.textbook.exercisedetail.data.ExerciseDetailSetupState;
import com.quizlet.explanations.textbook.exercisedetail.ui.ExerciseDetailFragment;
import com.quizlet.explanations.textbook.tableofcontents.ui.TableOfContentsFragment;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.ArrowOrientationRules;
import com.skydoves.balloon.ArrowPositionRules;
import com.skydoves.balloon.Balloon;
import com.skydoves.balloon.BalloonAnimation;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class d implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;

    public /* synthetic */ d(int i, Function0 function0) {
        this.a = 3;
        this.b = i;
        this.c = function0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int i = 3;
        Object obj2 = this.c;
        int i2 = this.b;
        switch (this.a) {
            case 0:
                p pVar = (p) obj;
                String str = TextbookFragment.l;
                TextbookFragment textbookFragment = (TextbookFragment) obj2;
                if (pVar instanceof o) {
                    String isbn = ((o) pVar).a;
                    AbstractC1136h0 childFragmentManager = textbookFragment.getChildFragmentManager();
                    int iJ = childFragmentManager.J();
                    for (int i3 = 0; i3 < iJ; i3++) {
                        childFragmentManager.V();
                    }
                    AbstractC1136h0 childFragmentManager2 = textbookFragment.getChildFragmentManager();
                    String str2 = TableOfContentsFragment.p;
                    if (childFragmentManager2.E(str2) == null) {
                        Intrinsics.checkNotNullParameter(isbn, "isbn");
                        TableOfContentsFragment tableOfContentsFragment = new TableOfContentsFragment();
                        Bundle bundle = new Bundle();
                        bundle.putString("ARG_TEXTBOOK_ISBN", isbn);
                        tableOfContentsFragment.setArguments(bundle);
                        textbookFragment.U(i2, tableOfContentsFragment, str2, false);
                    }
                } else if (pVar instanceof m) {
                    m mVar = (m) pVar;
                    String str3 = mVar.a;
                    textbookFragment.getClass();
                    String str4 = ChapterMenuFragment.n;
                    Bundle bundle2 = new Bundle();
                    bundle2.putBoolean("is_premium_text_book", mVar.b);
                    ChapterMenuFragment chapterMenuFragment = new ChapterMenuFragment();
                    chapterMenuFragment.setArguments(bundle2);
                    textbookFragment.U(i2, chapterMenuFragment, str3, true);
                } else if (pVar instanceof n) {
                    n nVar = (n) pVar;
                    ExerciseDetailSetupState setupState = nVar.a;
                    if (nVar.c) {
                        AbstractC1136h0 childFragmentManager3 = textbookFragment.getChildFragmentManager();
                        int iJ2 = childFragmentManager3.J();
                        for (int i4 = 0; i4 < iJ2; i4++) {
                            childFragmentManager3.V();
                        }
                    } else {
                        textbookFragment.getClass();
                    }
                    String str5 = ExerciseDetailFragment.y;
                    Intrinsics.checkNotNullParameter(setupState, "setupState");
                    Bundle bundle3 = new Bundle();
                    bundle3.putParcelable("exercise_detail_state", setupState);
                    ExerciseDetailFragment exerciseDetailFragment = new ExerciseDetailFragment();
                    exerciseDetailFragment.setArguments(bundle3);
                    textbookFragment.U(i2, exerciseDetailFragment, "ExerciseBackStackTag", nVar.b);
                } else if (Intrinsics.b(pVar, h.a)) {
                    textbookFragment.requireActivity().getOnBackPressedDispatcher().c();
                } else if (Intrinsics.b(pVar, i.a)) {
                    textbookFragment.getChildFragmentManager().V();
                } else {
                    if (!(pVar instanceof j)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    ((j) pVar).getClass();
                    AbstractC1136h0 childFragmentManager4 = textbookFragment.getChildFragmentManager();
                    childFragmentManager4.getClass();
                    childFragmentManager4.y(new C1132f0(childFragmentManager4, "ExerciseBackStackTag", -1, 1), false);
                }
                return Unit.a;
            case 1:
                androidx.compose.foundation.lazy.g LazyColumn = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn, "$this$LazyColumn");
                com.quizlet.search.data.term.a aVar = (com.quizlet.search.data.term.a) obj2;
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, -1903611243, new com.quizlet.features.notes.modals.e(aVar, i2)), 3);
                LazyColumn.q(aVar.g.size(), null, androidx.compose.foundation.lazy.o.c, new androidx.compose.runtime.internal.d(true, -1178861844, new v(aVar, i)));
                return Unit.a;
            case 2:
                V layout = (V) obj;
                Intrinsics.checkNotNullParameter(layout, "$this$layout");
                V.d(layout, (W) obj2, 0, -i2);
                return Unit.a;
            default:
                Balloon.Builder rememberBalloonBuilder = (Balloon.Builder) obj;
                Intrinsics.checkNotNullParameter(rememberBalloonBuilder, "$this$rememberBalloonBuilder");
                rememberBalloonBuilder.setVisibleArrow(true);
                rememberBalloonBuilder.setArrowDrawableResource(R.drawable.ic_sys_tip_with_padding);
                rememberBalloonBuilder.setArrowSizeResource(R.dimen.assembly_tooltip_arrow_size);
                rememberBalloonBuilder.setMarginTop(i2);
                rememberBalloonBuilder.m46setArrowPositionRules(ArrowPositionRules.ALIGN_ANCHOR);
                rememberBalloonBuilder.m44setArrowOrientationRules(ArrowOrientationRules.ALIGN_ANCHOR);
                rememberBalloonBuilder.setPaddingResource(R.dimen.ref_spacing_small);
                rememberBalloonBuilder.setCornerRadiusResource(R.dimen.ref_radius_medium);
                rememberBalloonBuilder.m53setBalloonAnimation(BalloonAnimation.FADE);
                rememberBalloonBuilder.setVisibleOverlay(false);
                rememberBalloonBuilder.m65setDismissWhenTouchOutside(false);
                rememberBalloonBuilder.m60setDismissWhenClicked(true);
                rememberBalloonBuilder.setOnBalloonDismissListener((Function0) obj2);
                return Unit.a;
        }
    }

    public /* synthetic */ d(Object obj, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.b = i;
    }
}
