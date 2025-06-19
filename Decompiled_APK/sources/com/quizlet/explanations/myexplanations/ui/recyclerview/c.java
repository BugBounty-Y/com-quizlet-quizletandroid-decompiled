package com.quizlet.explanations.myexplanations.ui.recyclerview;

import android.content.Context;
import android.view.View;
import androidx.compose.ui.platform.ComposeView;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3162h7;
import com.quizlet.explanations.questiondetail.ui.QuestionDetailFragment;
import com.quizlet.explanations.solution.recyclerview.step.k;
import com.quizlet.explanations.textbook.ui.TextbookFragment;
import com.quizlet.features.questiontypes.fitb.FillInTheBlankQuestionFragment;
import com.quizlet.features.questiontypes.mcq.MultipleChoiceQuestionFragment;
import com.quizlet.features.questiontypes.selfassessment.SelfAssessmentQuestionFragment;
import com.quizlet.features.questiontypes.truefalse.TrueFalseQuestionFragment;
import com.quizlet.features.questiontypes.written.WrittenQuestionFragment;
import com.quizlet.features.setpage.header.ui.SetPageHeaderFragment;
import com.quizlet.features.setpage.studypreview.StudyPreviewFragment;
import com.quizlet.features.setpage.termlist.TermListComposeFragment;
import com.quizlet.features.userprofile.ui.UserProfileFragment;
import com.quizlet.quizletandroid.ui.library.C4665j;
import com.quizlet.quizletandroid.ui.library.LibraryFragment;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.p;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.u;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.LAResultsFragment;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.LearnEndingFragment;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.LearnRoundSummaryFragment;
import com.quizlet.quizletandroid.ui.studymodes.testmode.fragments.TestModeResultsFragment;
import com.quizlet.quizletandroid.ui.studymodes.testmode.start.TestModeStartFragment;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements androidx.viewbinding.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        int i = 1;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                return ((d) obj).d;
            case 1:
                return ((g) obj).d;
            case 2:
                return ((i) obj).d;
            case 3:
                return ((com.quizlet.explanations.questiondetail.recyclerview.c) obj).d;
            case 4:
                return ((com.quizlet.explanations.questiondetail.recyclerview.i) obj).d;
            case 5:
                String str = QuestionDetailFragment.v;
                QuestionDetailFragment questionDetailFragment = (QuestionDetailFragment) obj;
                return AbstractC3162h7.b(questionDetailFragment, new androidx.compose.runtime.internal.d(true, 1058819178, new com.quizlet.explanations.questiondetail.ui.e(questionDetailFragment, i)));
            case 6:
                return ((k) obj).d;
            case 7:
                return ((com.quizlet.explanations.solution.solutionwall.limitedcontent.d) obj).d;
            case 8:
                return ((com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.g) obj).d;
            case 9:
                String str2 = TextbookFragment.l;
                TextbookFragment textbookFragment = (TextbookFragment) obj;
                return AbstractC3162h7.b(textbookFragment, new androidx.compose.runtime.internal.d(true, -455289047, new com.quizlet.explanations.textbook.ui.e(textbookFragment, i)));
            case 10:
                String str3 = FillInTheBlankQuestionFragment.k;
                FillInTheBlankQuestionFragment fillInTheBlankQuestionFragment = (FillInTheBlankQuestionFragment) obj;
                Context contextRequireContext = fillInTheBlankQuestionFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                ComposeView composeView = new ComposeView(contextRequireContext, null, 6);
                composeView.setContent(new androidx.compose.runtime.internal.d(true, -69928652, new com.quizlet.features.questiontypes.fitb.d(fillInTheBlankQuestionFragment, i)));
                return composeView;
            case 11:
                String str4 = MultipleChoiceQuestionFragment.k;
                MultipleChoiceQuestionFragment multipleChoiceQuestionFragment = (MultipleChoiceQuestionFragment) obj;
                Context contextRequireContext2 = multipleChoiceQuestionFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                ComposeView composeView2 = new ComposeView(contextRequireContext2, null, 6);
                composeView2.setContent(new androidx.compose.runtime.internal.d(true, 890700360, new com.quizlet.features.questiontypes.mcq.b(multipleChoiceQuestionFragment, i)));
                return composeView2;
            case 12:
                String str5 = SelfAssessmentQuestionFragment.k;
                SelfAssessmentQuestionFragment selfAssessmentQuestionFragment = (SelfAssessmentQuestionFragment) obj;
                Context contextRequireContext3 = selfAssessmentQuestionFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext3, "requireContext(...)");
                ComposeView composeView3 = new ComposeView(contextRequireContext3, null, 6);
                composeView3.setContent(new androidx.compose.runtime.internal.d(true, -1758840463, new com.quizlet.assembly.compose.cards.c(selfAssessmentQuestionFragment, 14)));
                return composeView3;
            case 13:
                String str6 = TrueFalseQuestionFragment.k;
                TrueFalseQuestionFragment trueFalseQuestionFragment = (TrueFalseQuestionFragment) obj;
                Context contextRequireContext4 = trueFalseQuestionFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext4, "requireContext(...)");
                ComposeView composeView4 = new ComposeView(contextRequireContext4, null, 6);
                composeView4.setContent(new androidx.compose.runtime.internal.d(true, -1291559560, new com.quizlet.features.questiontypes.truefalse.e(trueFalseQuestionFragment, i)));
                return composeView4;
            case 14:
                String str7 = WrittenQuestionFragment.k;
                WrittenQuestionFragment writtenQuestionFragment = (WrittenQuestionFragment) obj;
                Context contextRequireContext5 = writtenQuestionFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext5, "requireContext(...)");
                ComposeView composeView5 = new ComposeView(contextRequireContext5, null, 6);
                composeView5.setContent(new androidx.compose.runtime.internal.d(true, -755689738, new com.quizlet.features.questiontypes.written.f(writtenQuestionFragment, i)));
                return composeView5;
            case 15:
                String str8 = SetPageHeaderFragment.m;
                SetPageHeaderFragment setPageHeaderFragment = (SetPageHeaderFragment) obj;
                Context contextRequireContext6 = setPageHeaderFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext6, "requireContext(...)");
                ComposeView composeView6 = new ComposeView(contextRequireContext6, null, 6);
                composeView6.setContent(new androidx.compose.runtime.internal.d(true, 116490448, new com.quizlet.assembly.compose.cards.c(setPageHeaderFragment, 17)));
                return composeView6;
            case 16:
                String str9 = StudyPreviewFragment.k;
                StudyPreviewFragment studyPreviewFragment = (StudyPreviewFragment) obj;
                Context contextRequireContext7 = studyPreviewFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext7, "requireContext(...)");
                ComposeView composeView7 = new ComposeView(contextRequireContext7, null, 6);
                composeView7.setContent(new androidx.compose.runtime.internal.d(true, -2143971448, new com.quizlet.features.setpage.studypreview.a(studyPreviewFragment, i)));
                return composeView7;
            case 17:
                String str10 = TermListComposeFragment.m;
                TermListComposeFragment termListComposeFragment = (TermListComposeFragment) obj;
                Context contextRequireContext8 = termListComposeFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext8, "requireContext(...)");
                ComposeView composeView8 = new ComposeView(contextRequireContext8, null, 6);
                composeView8.setContent(new androidx.compose.runtime.internal.d(true, -891231131, new com.quizlet.assembly.compose.cards.c(termListComposeFragment, 18)));
                return composeView8;
            case 18:
                String str11 = UserProfileFragment.k;
                UserProfileFragment userProfileFragment = (UserProfileFragment) obj;
                Context contextRequireContext9 = userProfileFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext9, "requireContext(...)");
                ComposeView composeView9 = new ComposeView(contextRequireContext9, null, 6);
                composeView9.setContent(new androidx.compose.runtime.internal.d(true, -97637502, new com.quizlet.assembly.compose.cards.c(userProfileFragment, 23)));
                return composeView9;
            case 19:
                String str12 = LibraryFragment.n;
                LibraryFragment libraryFragment = (LibraryFragment) obj;
                libraryFragment.getClass();
                Context contextRequireContext10 = libraryFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext10, "requireContext(...)");
                ComposeView composeView10 = new ComposeView(contextRequireContext10, null, 6);
                composeView10.setContent(new androidx.compose.runtime.internal.d(true, -1755984333, new C4665j(libraryFragment, i)));
                return composeView10;
            case 20:
                return ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.c) obj).d;
            case 21:
                return ((com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.d) obj).d;
            case EventType.WINDOW_STATE /* 22 */:
                return ((com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.f) obj).d;
            case EventType.AUDIO /* 23 */:
                return ((p) obj).e;
            case EventType.VIDEO /* 24 */:
                return ((u) obj).d;
            case EventType.SUBS /* 25 */:
                String str13 = LAResultsFragment.n;
                LAResultsFragment lAResultsFragment = (LAResultsFragment) obj;
                Context contextRequireContext11 = lAResultsFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext11, "requireContext(...)");
                ComposeView composeView11 = new ComposeView(contextRequireContext11, null, 6);
                composeView11.setContent(new androidx.compose.runtime.internal.d(true, -1805867962, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.c(lAResultsFragment, 0)));
                return composeView11;
            case EventType.CDN /* 26 */:
                String str14 = LearnEndingFragment.m;
                LearnEndingFragment learnEndingFragment = (LearnEndingFragment) obj;
                Context contextRequireContext12 = learnEndingFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext12, "requireContext(...)");
                ComposeView composeView12 = new ComposeView(contextRequireContext12, null, 6);
                composeView12.setContent(new androidx.compose.runtime.internal.d(true, 434343575, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.c(learnEndingFragment, i)));
                return composeView12;
            case 27:
                LearnRoundSummaryFragment learnRoundSummaryFragment = (LearnRoundSummaryFragment) obj;
                Context contextRequireContext13 = learnRoundSummaryFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext13, "requireContext(...)");
                ComposeView composeView13 = new ComposeView(contextRequireContext13, null, 6);
                composeView13.setContent(new androidx.compose.runtime.internal.d(true, 1236755831, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.p(learnRoundSummaryFragment, i)));
                return composeView13;
            case 28:
                TestModeResultsFragment testModeResultsFragment = (TestModeResultsFragment) obj;
                Context contextRequireContext14 = testModeResultsFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext14, "requireContext(...)");
                ComposeView composeView14 = new ComposeView(contextRequireContext14, null, 6);
                composeView14.setContent(new androidx.compose.runtime.internal.d(true, 1260310825, new com.quizlet.quizletandroid.ui.studymodes.testmode.fragments.a(testModeResultsFragment, i)));
                return composeView14;
            default:
                String str15 = TestModeStartFragment.l;
                TestModeStartFragment testModeStartFragment = (TestModeStartFragment) obj;
                Context contextRequireContext15 = testModeStartFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext15, "requireContext(...)");
                ComposeView composeView15 = new ComposeView(contextRequireContext15, null, 6);
                composeView15.setContent(new androidx.compose.runtime.internal.d(true, -1199711064, new com.quizlet.quizletandroid.ui.studymodes.testmode.start.k(testModeStartFragment, i)));
                return composeView15;
        }
    }
}
