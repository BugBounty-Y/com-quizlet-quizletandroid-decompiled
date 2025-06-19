package com.facebook.internal;

import android.content.DialogInterface;
import android.view.View;
import androidx.lifecycle.p0;
import com.quizlet.explanations.questiondetail.ui.QuestionDetailFragment;
import com.quizlet.explanations.textbook.ui.TextbookFragment;
import com.quizlet.features.onboarding.ell.OnboardingELLBottomSheetFragment;
import com.quizlet.quizletandroid.ui.studymodes.assistant.LearningAssistantActivity;
import com.quizlet.quizletandroid.ui.studymodes.testmode.activities.TestStudyModeActivity;
import com.quizlet.quizletandroid.ui.usersettings.fragments.ChangeProfileImageFragment;
import com.quizlet.search.TermSearchFragment;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class K implements DialogInterface.OnCancelListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ View.OnCreateContextMenuListener b;

    public /* synthetic */ K(View.OnCreateContextMenuListener onCreateContextMenuListener, int i) {
        this.a = i;
        this.b = onCreateContextMenuListener;
    }

    @Override // android.content.DialogInterface.OnCancelListener
    public final void onCancel(DialogInterface dialogInterface) {
        View.OnCreateContextMenuListener onCreateContextMenuListener = this.b;
        switch (this.a) {
            case 0:
                S this$0 = (S) onCreateContextMenuListener;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                this$0.cancel();
                break;
            case 1:
                String str = QuestionDetailFragment.v;
                Intrinsics.d(dialogInterface);
                QuestionDetailFragment questionDetailFragment = (QuestionDetailFragment) onCreateContextMenuListener;
                questionDetailFragment.getClass();
                dialogInterface.dismiss();
                questionDetailFragment.requireActivity().getOnBackPressedDispatcher().c();
                break;
            case 2:
                String str2 = TextbookFragment.l;
                Intrinsics.d(dialogInterface);
                TextbookFragment textbookFragment = (TextbookFragment) onCreateContextMenuListener;
                textbookFragment.getClass();
                dialogInterface.dismiss();
                textbookFragment.requireActivity().getOnBackPressedDispatcher().c();
                break;
            case 3:
                String str3 = OnboardingELLBottomSheetFragment.w;
                com.quizlet.features.onboarding.ell.B b = (com.quizlet.features.onboarding.ell.B) ((OnboardingELLBottomSheetFragment) onCreateContextMenuListener).v.getValue();
                com.quizlet.features.onboarding.ell.h onboardingELLEvent = com.quizlet.features.onboarding.ell.h.a;
                b.getClass();
                Intrinsics.checkNotNullParameter(onboardingELLEvent, "onboardingELLEvent");
                kotlinx.coroutines.E.A(p0.j(b), null, null, new com.quizlet.features.onboarding.ell.A(onboardingELLEvent, b, null), 3);
                break;
            case 4:
                String str4 = LearningAssistantActivity.D;
                ((LearningAssistantActivity) onCreateContextMenuListener).finish();
                break;
            case 5:
                String str5 = TestStudyModeActivity.v;
                ((TestStudyModeActivity) onCreateContextMenuListener).finish();
                break;
            case 6:
                String str6 = ChangeProfileImageFragment.w;
                ChangeProfileImageFragment changeProfileImageFragment = (ChangeProfileImageFragment) onCreateContextMenuListener;
                if (changeProfileImageFragment.getTargetFragment() == null) {
                    changeProfileImageFragment.getActivity().setResult(0, null);
                    changeProfileImageFragment.getActivity().finish();
                    break;
                } else {
                    changeProfileImageFragment.getTargetFragment().onActivityResult(changeProfileImageFragment.getTargetRequestCode(), 0, null);
                    break;
                }
            default:
                String str7 = TermSearchFragment.V;
                ((TermSearchFragment) onCreateContextMenuListener).H(false, false);
                dialogInterface.dismiss();
                break;
        }
    }
}
