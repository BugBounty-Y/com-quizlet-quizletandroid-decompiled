package com.quizlet.explanations.questiondetail.ui;

import android.content.DialogInterface;
import com.quizlet.explanations.textbook.ui.TextbookFragment;
import com.quizlet.quizletandroid.ui.common.views.DatePickerDialogFragment;
import com.quizlet.quizletandroid.ui.studymodes.assistant.LearningAssistantActivity;
import com.quizlet.quizletandroid.ui.studymodes.testmode.activities.TestStudyModeActivity;
import com.quizlet.search.TermSearchFragment;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.EnumC5145a;

/* loaded from: classes2.dex */
public final /* synthetic */ class d implements DialogInterface.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ d(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.content.DialogInterface.OnClickListener
    public final void onClick(DialogInterface dialogInterface, int i) {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                String str = QuestionDetailFragment.v;
                Intrinsics.d(dialogInterface);
                QuestionDetailFragment questionDetailFragment = (QuestionDetailFragment) obj;
                questionDetailFragment.getClass();
                dialogInterface.dismiss();
                questionDetailFragment.requireActivity().getOnBackPressedDispatcher().c();
                break;
            case 1:
                String str2 = TextbookFragment.l;
                Intrinsics.d(dialogInterface);
                TextbookFragment textbookFragment = (TextbookFragment) obj;
                textbookFragment.getClass();
                dialogInterface.dismiss();
                textbookFragment.requireActivity().getOnBackPressedDispatcher().c();
                break;
            case 2:
                ((DatePickerDialogFragment) obj).H(false, false);
                break;
            case 3:
                String str3 = LearningAssistantActivity.D;
                ((LearningAssistantActivity) obj).finish();
                break;
            case 4:
                String str4 = TestStudyModeActivity.v;
                ((TestStudyModeActivity) obj).finish();
                break;
            case 5:
                String str5 = TermSearchFragment.V;
                ((TermSearchFragment) obj).H(false, false);
                dialogInterface.dismiss();
                break;
            default:
                EnumC5145a enumC5145a = AztecText.q1;
                AztecText this$0 = (AztecText) obj;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                this$0.o();
                break;
        }
    }
}
