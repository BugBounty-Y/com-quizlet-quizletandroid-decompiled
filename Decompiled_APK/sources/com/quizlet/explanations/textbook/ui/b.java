package com.quizlet.explanations.textbook.ui;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.InterfaceC1144l0;
import com.quizlet.explanations.textbook.exercisedetail.ui.ExerciseDetailFragment;
import com.quizlet.features.infra.snackbar.n;
import com.quizlet.features.setpage.r;
import com.quizlet.quizletandroid.ui.diagramming.DiagramOverviewActivity;
import com.quizlet.quizletandroid.ui.diagramming.DiagramOverviewFragment;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import java.lang.ref.WeakReference;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class b implements InterfaceC1144l0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ b(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // androidx.fragment.app.InterfaceC1144l0
    public final void a(AbstractC1136h0 abstractC1136h0, Fragment fragment) {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                String str = TextbookFragment.l;
                Intrinsics.checkNotNullParameter(abstractC1136h0, "<unused var>");
                Intrinsics.checkNotNullParameter(fragment, "<unused var>");
                TextbookFragment textbookFragment = (TextbookFragment) obj;
                InterfaceC0773a0 interfaceC0773a0 = textbookFragment.k;
                List listF = textbookFragment.getChildFragmentManager().c.f();
                Intrinsics.checkNotNullExpressionValue(listF, "getFragments(...)");
                ((L0) interfaceC0773a0).setValue(Boolean.valueOf(CollectionsKt.firstOrNull(listF) instanceof ExerciseDetailFragment));
                break;
            case 1:
                Intrinsics.checkNotNullParameter(abstractC1136h0, "<unused var>");
                Intrinsics.checkNotNullParameter(fragment, "fragment");
                if ((fragment instanceof n ? (n) fragment : null) != null) {
                    r provider = (r) obj;
                    Intrinsics.checkNotNullParameter(provider, "provider");
                    break;
                }
                break;
            case 2:
                int i = DiagramOverviewActivity.o1;
                Intrinsics.checkNotNullParameter(abstractC1136h0, "<unused var>");
                Intrinsics.checkNotNullParameter(fragment, "fragment");
                if (fragment instanceof DiagramOverviewFragment) {
                    ((DiagramOverviewFragment) fragment).l = (DiagramOverviewActivity) obj;
                    break;
                }
                break;
            default:
                com.quizlet.quizletandroid.ui.setcreation.activities.d presenter = (com.quizlet.quizletandroid.ui.setcreation.activities.d) obj;
                if (fragment instanceof EditSetFragment) {
                    Intrinsics.checkNotNullParameter(presenter, "presenter");
                    ((EditSetFragment) fragment).x = new WeakReference(presenter);
                    break;
                }
                break;
        }
    }
}
