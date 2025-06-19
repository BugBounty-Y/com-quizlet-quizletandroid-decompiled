package androidx.navigation.compose;

import android.content.Intent;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3153g7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3182k0;
import com.google.android.gms.internal.mlkit_vision_barcode.U;
import com.google.android.gms.internal.mlkit_vision_camera.L1;
import com.google.android.gms.internal.mlkit_vision_camera.N2;
import com.google.android.gms.internal.mlkit_vision_camera.Q1;
import com.google.android.gms.internal.mlkit_vision_camera.X1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3473j;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3479k;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3485l;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3491m;
import com.google.android.gms.internal.mlkit_vision_common.I2;
import com.quizlet.baseui.base.BaseComposeBottomSheetFragment;
import com.quizlet.data.model.O;
import com.quizlet.data.model.T;
import com.quizlet.data.model.X0;
import com.quizlet.explanations.questiondetail.ui.QuestionDetailFragment;
import com.quizlet.explanations.textbook.ui.TextbookFragment;
import com.quizlet.features.emailconfirmation.ui.activities.EmailConfirmationActivity;
import com.quizlet.features.emailconfirmation.ui.activities.MagicLinkConfirmationActivity;
import com.quizlet.features.questiontypes.fitb.FillInTheBlankQuestionFragment;
import com.quizlet.features.questiontypes.mcq.MultipleChoiceQuestionFragment;
import com.quizlet.features.questiontypes.selfassessment.SelfAssessmentQuestionFragment;
import com.quizlet.features.questiontypes.truefalse.TrueFalseQuestionFragment;
import com.quizlet.features.questiontypes.written.WrittenQuestionFragment;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.features.setpage.header.ui.SetPageHeaderFragment;
import com.quizlet.features.setpage.studypreview.StudyPreviewFragment;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.navigation.compose.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1278k implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ C1278k(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) throws Exception {
        Object obj3 = this.b;
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                L1.a((s) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 1:
                ((Integer) obj2).getClass();
                ((BaseComposeBottomSheetFragment) obj3).Q((InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 2:
                ((Integer) obj2).getClass();
                String str = QuestionDetailFragment.v;
                ((QuestionDetailFragment) obj3).T((InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 3:
                ((Integer) obj2).getClass();
                com.quizlet.features.universaluploadflow.navigation.c.c((com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.d) obj3, (InterfaceC0806l) obj, C0776c.H(49));
                break;
            case 4:
                ((Integer) obj2).getClass();
                String str2 = TextbookFragment.l;
                ((TextbookFragment) obj3).T((InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 5:
                ((Integer) obj2).getClass();
                com.facebook.appevents.m.m((com.quizlet.features.achievements.achievement.l) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 6:
                ((Integer) obj2).getClass();
                com.google.android.exoplayer2.drm.b.f((O) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 7:
                ((Integer) obj2).getClass();
                String str3 = EmailConfirmationActivity.r;
                ((EmailConfirmationActivity) obj3).P((InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 8:
                ((Integer) obj2).getClass();
                String str4 = MagicLinkConfirmationActivity.r;
                ((MagicLinkConfirmationActivity) obj3).P((InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 9:
                ((Integer) obj2).getClass();
                com.quizlet.features.emailconfirmation.ui.composables.y.a((com.quizlet.features.emailconfirmation.viewmodel.g) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 10:
                ((Integer) obj2).getClass();
                U.a((com.quizlet.features.emailconfirmation.viewmodel.h) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 11:
                ((Integer) obj2).getClass();
                AbstractC3182k0.c((kotlinx.collections.immutable.b) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 12:
                ((Integer) obj2).getClass();
                AbstractC3153g7.c((T) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 13:
                androidx.activity.compose.o launcher = (androidx.activity.compose.o) obj;
                long jLongValue = ((Long) obj2).longValue();
                Intrinsics.checkNotNullParameter(launcher, "launcher");
                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar = (com.quizlet.quizletandroid.ui.navigationmanagers.e) ((com.quizlet.features.notes.manager.a) obj3);
                eVar.getClass();
                Intrinsics.checkNotNullParameter(launcher, "launcher");
                Intent intentB = com.quizlet.features.setpage.e.b(SetPageActivity.h1, eVar.a, jLongValue, null, null, null, Boolean.TRUE, true, null, 156);
                intentB.setFlags(131072);
                launcher.a(intentB);
                break;
            case 14:
                ((Integer) obj2).getClass();
                Q1.g((com.quizlet.features.practicetest.common.data.j) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 15:
                ((Integer) obj2).getClass();
                X1.b((X0) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 16:
                ((Integer) obj2).getClass();
                String str5 = FillInTheBlankQuestionFragment.k;
                ((FillInTheBlankQuestionFragment) obj3).T((InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 17:
                ((Integer) obj2).getClass();
                com.quizlet.features.questiontypes.fitb.ui.l.d((N2) obj3, (InterfaceC0806l) obj, C0776c.H(7));
                break;
            case 18:
                ((Integer) obj2).getClass();
                String str6 = MultipleChoiceQuestionFragment.k;
                ((MultipleChoiceQuestionFragment) obj3).T((InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 19:
                ((Integer) obj2).getClass();
                String str7 = SelfAssessmentQuestionFragment.k;
                ((SelfAssessmentQuestionFragment) obj3).T((InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 20:
                ((Integer) obj2).getClass();
                String str8 = TrueFalseQuestionFragment.k;
                ((TrueFalseQuestionFragment) obj3).T((InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 21:
                ((Integer) obj2).getClass();
                String str9 = WrittenQuestionFragment.k;
                ((WrittenQuestionFragment) obj3).T((InterfaceC0806l) obj, C0776c.H(1));
                break;
            case EventType.WINDOW_STATE /* 22 */:
                String response = (String) obj;
                boolean zBooleanValue = ((Boolean) obj2).booleanValue();
                Intrinsics.checkNotNullParameter(response, "response");
                ((com.quizlet.features.questiontypes.written.o) ((com.quizlet.features.questiontypes.written.a) obj3)).F(new com.quizlet.features.questiontypes.written.b(response, zBooleanValue));
                break;
            case EventType.AUDIO /* 23 */:
                ((Integer) obj2).getClass();
                AbstractC3473j.a((com.quizlet.features.questiontypes.written.data.b) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case EventType.VIDEO /* 24 */:
                ((Integer) obj2).getClass();
                AbstractC3479k.a((com.quizlet.features.questiontypes.written.data.c) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case EventType.SUBS /* 25 */:
                ((Integer) obj2).getClass();
                AbstractC3485l.a((com.quizlet.features.questiontypes.written.data.d) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case EventType.CDN /* 26 */:
                ((Integer) obj2).getClass();
                AbstractC3491m.a((com.quizlet.features.questiontypes.written.data.e) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 27:
                ((Integer) obj2).getClass();
                String str10 = SetPageHeaderFragment.m;
                ((SetPageHeaderFragment) obj3).T((InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 28:
                ((Integer) obj2).getClass();
                String str11 = StudyPreviewFragment.k;
                ((StudyPreviewFragment) obj3).T((InterfaceC0806l) obj, C0776c.H(1));
                break;
            default:
                ((Integer) obj2).getClass();
                I2.a((com.quizlet.features.settings.composables.n) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ C1278k(Object obj, int i, int i2) {
        this.a = i2;
        this.b = obj;
    }
}
