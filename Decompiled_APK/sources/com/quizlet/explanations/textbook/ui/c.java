package com.quizlet.explanations.textbook.ui;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.InterfaceC1128d0;
import com.quizlet.explanations.textbook.exercisedetail.ui.ExerciseDetailFragment;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.dialogs.FullScreenConvertibleModalDialogFragment;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements InterfaceC1128d0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Fragment b;

    public /* synthetic */ c(Fragment fragment, int i) {
        this.a = i;
        this.b = fragment;
    }

    @Override // androidx.fragment.app.InterfaceC1128d0
    public final void a() {
        switch (this.a) {
            case 0:
                TextbookFragment textbookFragment = (TextbookFragment) this.b;
                InterfaceC0773a0 interfaceC0773a0 = textbookFragment.k;
                List listF = textbookFragment.getChildFragmentManager().c.f();
                Intrinsics.checkNotNullExpressionValue(listF, "getFragments(...)");
                ((L0) interfaceC0773a0).setValue(Boolean.valueOf(CollectionsKt.firstOrNull(listF) instanceof ExerciseDetailFragment));
                break;
            default:
                FullScreenConvertibleModalDialogFragment fullScreenConvertibleModalDialogFragment = (FullScreenConvertibleModalDialogFragment) this.b;
                if (fullScreenConvertibleModalDialogFragment.getChildFragmentManager().J() <= 0) {
                    ((com.quizlet.quizletandroid.ui.common.databinding.a) fullScreenConvertibleModalDialogFragment.P()).c.setImageResource(R.drawable.ic_sys_close_x);
                    break;
                } else {
                    ((com.quizlet.quizletandroid.ui.common.databinding.a) fullScreenConvertibleModalDialogFragment.P()).c.setImageResource(R.drawable.ic_sys_caret_left);
                    break;
                }
        }
    }
}
