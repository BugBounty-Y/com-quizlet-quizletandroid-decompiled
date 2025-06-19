package com.quizlet.features.setpage.progress.presentation.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.lifecycle.compose.d;
import com.features.flashcards.creatormarketing.h;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.explanations.databinding.n;
import com.quizlet.features.infra.legacyadapter.databinding.f;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.G;
import com.quizlet.features.setpage.databinding.c;
import com.quizlet.features.setpage.viewmodel.C4428b;
import com.quizlet.features.setpage.viewmodel.D;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.views.ArcProgressBar;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class SetPageProgressFragment extends Hilt_SetPageProgressFragment<c> {
    public static final String l;
    public final e j = new e(K.a(com.quizlet.features.setpage.progress.presentation.viewmodel.a.class), new a(this, 0), new a(this, 2), new a(this, 1));
    public final e k = new e(K.a(P.class), new a(this, 3), new a(this, 5), new a(this, 4));

    static {
        Intrinsics.checkNotNullExpressionValue("SetPageProgressFragment", "getSimpleName(...)");
        l = "SetPageProgressFragment";
    }

    public static void T(SetPageProgressFragment setPageProgressFragment, View view) {
        com.quizlet.features.setpage.progress.a progressBucket;
        e eVar = setPageProgressFragment.j;
        com.quizlet.features.setpage.progress.b bVar = (com.quizlet.features.setpage.progress.b) ((com.quizlet.features.setpage.progress.presentation.viewmodel.a) eVar.getValue()).h.d();
        if (bVar == null || (progressBucket = setPageProgressFragment.U(view)) == null) {
            return;
        }
        P p = (P) setPageProgressFragment.k.getValue();
        List progressTermIds = bVar.a(progressBucket);
        p.getClass();
        Intrinsics.checkNotNullParameter(progressTermIds, "progressTermIds");
        p.I(new C4428b(p, 0), new D(p, progressTermIds, null));
        com.quizlet.features.setpage.progress.presentation.viewmodel.a aVar = (com.quizlet.features.setpage.progress.presentation.viewmodel.a) eVar.getValue();
        aVar.getClass();
        Intrinsics.checkNotNullParameter(progressBucket, "progressBucket");
        com.quizlet.features.setpage.progress.b progressData = (com.quizlet.features.setpage.progress.b) aVar.h.d();
        if (progressData != null) {
            h hVar = aVar.d;
            hVar.getClass();
            Intrinsics.checkNotNullParameter(progressData, "progressData");
            Intrinsics.checkNotNullParameter(progressBucket, "progressBucket");
            EventLoggerExt.c(hVar.a, new d(progressBucket, hVar, progressData, 19));
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return l;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_set_page_progress, viewGroup, false);
        ConstraintLayout constraintLayout = (ConstraintLayout) viewInflate;
        int i = R.id.progress_desc;
        if (((QTextView) AbstractC3375o2.c(R.id.progress_desc, viewInflate)) != null) {
            i = R.id.progressItems;
            View viewC = AbstractC3375o2.c(R.id.progressItems, viewInflate);
            if (viewC != null) {
                int i2 = R.id.progressItemLearning;
                SetPageProgressItemView setPageProgressItemView = (SetPageProgressItemView) AbstractC3375o2.c(R.id.progressItemLearning, viewC);
                if (setPageProgressItemView != null) {
                    i2 = R.id.progressItemMastered;
                    SetPageProgressItemView setPageProgressItemView2 = (SetPageProgressItemView) AbstractC3375o2.c(R.id.progressItemMastered, viewC);
                    if (setPageProgressItemView2 != null) {
                        i2 = R.id.progressItemNotStarted;
                        SetPageProgressItemView setPageProgressItemView3 = (SetPageProgressItemView) AbstractC3375o2.c(R.id.progressItemNotStarted, viewC);
                        if (setPageProgressItemView3 != null) {
                            f fVar = new f((LinearLayout) viewC, setPageProgressItemView, setPageProgressItemView2, setPageProgressItemView3, 1);
                            i = R.id.progress_title;
                            if (((QTextView) AbstractC3375o2.c(R.id.progress_title, viewInflate)) != null) {
                                c cVar = new c(constraintLayout, fVar);
                                Intrinsics.checkNotNullExpressionValue(cVar, "inflate(...)");
                                return cVar;
                            }
                        }
                    }
                }
                throw new NullPointerException("Missing required view with ID: ".concat(viewC.getResources().getResourceName(i2)));
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final com.quizlet.features.setpage.progress.a U(View view) {
        if (Intrinsics.b(view, (SetPageProgressItemView) ((c) J()).b.e)) {
            return com.quizlet.features.setpage.progress.a.b;
        }
        if (Intrinsics.b(view, (SetPageProgressItemView) ((c) J()).b.c)) {
            return com.quizlet.features.setpage.progress.a.c;
        }
        if (Intrinsics.b(view, (SetPageProgressItemView) ((c) J()).b.d)) {
            return com.quizlet.features.setpage.progress.a.d;
        }
        return null;
    }

    public final void V(SetPageProgressItemView setPageProgressItemView, com.quizlet.features.setpage.progress.b bVar) {
        List listA;
        com.quizlet.features.setpage.progress.a aVarU = U(setPageProgressItemView);
        if (aVarU == null || (listA = bVar.a(aVarU)) == null) {
            listA = kotlin.collections.K.a;
        }
        int size = listA.size();
        int iB = bVar.b();
        n nVar = setPageProgressItemView.h;
        ((ArcProgressBar) nVar.g).setProgress(iB > 0 ? (size * 100) / iB : 0);
        ((QTextView) nVar.d).setText(String.valueOf(size));
        setPageProgressItemView.setEnabled(size > 0);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        e eVar = this.j;
        ((com.quizlet.features.setpage.progress.presentation.viewmodel.a) eVar.getValue()).h.f(this, new com.quizlet.ads.ui.fragments.c(new G(1, this, SetPageProgressFragment.class, "updateProgress", "updateProgress(Lcom/quizlet/features/setpage/progress/ProgressData;)V", 0, 26), (char) 0));
        com.quizlet.features.setpage.progress.presentation.viewmodel.a aVar = (com.quizlet.features.setpage.progress.presentation.viewmodel.a) eVar.getValue();
        aVar.g.c();
        com.quizlet.data.repository.user.e eVar2 = aVar.j;
        ((com.quizlet.features.infra.studysetting.datasource.a) eVar2.b).d();
        ((com.quizlet.features.infra.studysetting.datasource.a) eVar2.c).d();
        ((io.reactivex.rxjava3.subjects.d) ((com.quizlet.data.repository.explanations.exercise.b) eVar2.d).c).b(Unit.a);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        ((SetPageProgressItemView) ((c) J()).b.e).setOnClickListener(new com.braze.ui.inappmessage.d(this, 28));
        ((SetPageProgressItemView) ((c) J()).b.c).setOnClickListener(new com.braze.ui.inappmessage.d(this, 28));
        ((SetPageProgressItemView) ((c) J()).b.d).setOnClickListener(new com.braze.ui.inappmessage.d(this, 28));
    }
}
