package assistantMode.experiments;

import android.widget.ImageView;
import androidx.lifecycle.C0;
import assistantMode.refactored.modelTypes.DiagramShapeValue;
import assistantMode.types.C1454a;
import assistantMode.types.aliases.ExperimentConfiguration;
import assistantMode.types.h;
import com.amazon.aps.ads.activity.ApsInterstitialActivity;
import com.comscore.streaming.EventType;
import com.facebook.appevents.g;
import com.google.android.gms.internal.mlkit_vision_camera.A2;
import com.onetrust.otpublishers.headless.UI.fragment.C;
import com.onetrust.otpublishers.headless.UI.fragment.C4061e;
import com.quizlet.edgy.ui.fragment.EdgyAddCourseManuallyFragment;
import com.quizlet.edgy.ui.fragment.EdgyAddSchoolManuallyFragment;
import com.quizlet.edgy.ui.fragment.EdgyModalFragment;
import com.quizlet.explanations.feedback.ui.fragments.ExplanationsFeedbackFragment;
import com.quizlet.explanations.textbook.chaptermenu.ui.ChapterMenuFragment;
import com.quizlet.explanations.textbook.ui.TextbookFragment;
import com.quizlet.features.achievements.ui.AchievementsFragment;
import com.quizlet.features.infra.folder.create.CreateFolderModalFragment;
import com.quizlet.features.setpage.terms.ui.SelectedTermsModeFragment;
import com.quizlet.login.recovery.forgotpassword.ui.ForgotPasswordDialogFragment;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class a extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(Object obj, int i) {
        super(0);
        this.a = i;
        this.b = obj;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return A2.b(new androidx.credentials.playservices.controllers.BeginSignIn.c((ExperimentConfiguration) this.b, 9));
            case 1:
                h hVar = ((C1454a) this.b).d;
                if (hVar == null) {
                    return null;
                }
                return new DiagramShapeValue(hVar.b);
            case 2:
                ApsInterstitialActivity apsInterstitialActivity = (ApsInterstitialActivity) this.b;
                ImageView imageView = new ImageView(apsInterstitialActivity);
                imageView.setImageDrawable(g.f(apsInterstitialActivity, 2131231642));
                return imageView;
            case 3:
                return new androidx.vectordrawable.graphics.drawable.c((com.google.accompanist.drawablepainter.a) this.b, 1);
            case 4:
                return ((C4061e) this.b).b;
            case 5:
                return ((com.onetrust.otpublishers.headless.UI.fragment.r) this.b).b;
            case 6:
                return ((C) this.b).b;
            case 7:
                return (EdgyAddCourseManuallyFragment) this.b;
            case 8:
                return (C0) ((a) this.b).invoke();
            case 9:
                return (EdgyAddSchoolManuallyFragment) this.b;
            case 10:
                return (C0) ((a) this.b).invoke();
            case 11:
                return (EdgyModalFragment) this.b;
            case 12:
                return (C0) ((a) this.b).invoke();
            case 13:
                return (ExplanationsFeedbackFragment) this.b;
            case 14:
                return (C0) ((a) this.b).invoke();
            case 15:
                return (C0) ((com.quizlet.explanations.questiondetail.ui.g) this.b).invoke();
            case 16:
                return (C0) ((com.quizlet.explanations.questiondetail.ui.g) this.b).invoke();
            case 17:
                return (ChapterMenuFragment) this.b;
            case 18:
                return (C0) ((a) this.b).invoke();
            case 19:
                return (C0) ((com.quizlet.explanations.textbook.exercisedetail.ui.d) this.b).invoke();
            case 20:
                return (C0) ((com.quizlet.explanations.textbook.exercisedetail.ui.d) this.b).invoke();
            case 21:
                return (TextbookFragment) this.b;
            case EventType.WINDOW_STATE /* 22 */:
                return (C0) ((a) this.b).invoke();
            case EventType.AUDIO /* 23 */:
                return (AchievementsFragment) this.b;
            case EventType.VIDEO /* 24 */:
                return (C0) ((a) this.b).invoke();
            case EventType.SUBS /* 25 */:
                return (CreateFolderModalFragment) this.b;
            case EventType.CDN /* 26 */:
                return (C0) ((a) this.b).invoke();
            case 27:
                return (SelectedTermsModeFragment) this.b;
            case 28:
                return (C0) ((a) this.b).invoke();
            default:
                return (ForgotPasswordDialogFragment) this.b;
        }
    }
}
