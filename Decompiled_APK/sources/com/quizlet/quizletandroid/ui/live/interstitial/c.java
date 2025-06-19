package com.quizlet.quizletandroid.ui.live.interstitial;

import android.content.Intent;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.quizlet.assembly.widgets.buttons.AssemblyTextButton;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.wrappers.LoggedInUserStatus;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.N;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.data.repository.classmembership.c b;

    public /* synthetic */ c(com.quizlet.data.repository.classmembership.c cVar, int i) {
        this.a = i;
        this.b = cVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                LoggedInUserStatus userStatus = (LoggedInUserStatus) obj;
                Intrinsics.checkNotNullParameter(userStatus, "userStatus");
                DBUser currentUser = userStatus.getCurrentUser();
                int selfIdentifiedUserType = currentUser != null ? currentUser.getSelfIdentifiedUserType() : 0;
                com.quizlet.data.repository.classmembership.c cVar = this.b;
                com.quizlet.features.emailconfirmation.logging.a aVar = (com.quizlet.features.emailconfirmation.logging.a) cVar.b;
                if (selfIdentifiedUserType != 1) {
                    aVar.a.x("quizlet_live_did_tap_share_with_teacher");
                    QuizletLiveInterstitialActivity quizletLiveInterstitialActivity = (QuizletLiveInterstitialActivity) cVar.c();
                    Intent intent = new Intent();
                    intent.setAction("android.intent.action.SEND");
                    intent.putExtra("android.intent.extra.TEXT", quizletLiveInterstitialActivity.getString(R.string.quizlet_live_share));
                    intent.setType("text/plain");
                    quizletLiveInterstitialActivity.startActivity(Intent.createChooser(intent, quizletLiveInterstitialActivity.getString(R.string.secondary_action_student_text)));
                    break;
                } else {
                    aVar.a.x("quizlet_live_did_tap_learn_more");
                    QuizletLiveInterstitialActivity quizletLiveInterstitialActivity2 = (QuizletLiveInterstitialActivity) cVar.c();
                    Intrinsics.checkNotNullParameter("https://www.youtube.com/watch?v=q64qTBfK0iE", DTBMetricsConfiguration.APSMETRICS_URL);
                    com.quizlet.quizletandroid.ui.webpages.a.a.b(quizletLiveInterstitialActivity2, "https://www.youtube.com/watch?v=q64qTBfK0iE", null);
                    break;
                }
            default:
                LoggedInUserStatus userStatus2 = (LoggedInUserStatus) obj;
                Intrinsics.checkNotNullParameter(userStatus2, "userStatus");
                DBUser currentUser2 = userStatus2.getCurrentUser();
                int selfIdentifiedUserType2 = currentUser2 != null ? currentUser2.getSelfIdentifiedUserType() : 0;
                com.quizlet.data.repository.classmembership.c cVar2 = this.b;
                if (selfIdentifiedUserType2 != 1) {
                    QTextView interstitialHeader = ((N) ((QuizletLiveInterstitialActivity) cVar2.c()).K()).f;
                    Intrinsics.checkNotNullExpressionValue(interstitialHeader, "interstitialHeader");
                    interstitialHeader.setText(R.string.quizlet_live_interstitial_student_header_text);
                    QTextView interstitialSubText = ((N) ((QuizletLiveInterstitialActivity) cVar2.c()).K()).g;
                    Intrinsics.checkNotNullExpressionValue(interstitialSubText, "interstitialSubText");
                    interstitialSubText.setText(R.string.quizlet_live_interstitial_student_sub_text);
                    DBUser currentUser3 = userStatus2.getCurrentUser();
                    if (currentUser3 != null && currentUser3.getIsUnderAge()) {
                        AssemblyTextButton btnSecondaryAction = ((N) ((QuizletLiveInterstitialActivity) cVar2.c()).K()).c;
                        Intrinsics.checkNotNullExpressionValue(btnSecondaryAction, "btnSecondaryAction");
                        btnSecondaryAction.setVisibility(8);
                        break;
                    } else {
                        AssemblyTextButton btnSecondaryAction2 = ((N) ((QuizletLiveInterstitialActivity) cVar2.c()).K()).c;
                        Intrinsics.checkNotNullExpressionValue(btnSecondaryAction2, "btnSecondaryAction");
                        btnSecondaryAction2.setText(R.string.secondary_action_student_text);
                        break;
                    }
                } else {
                    QTextView interstitialHeader2 = ((N) ((QuizletLiveInterstitialActivity) cVar2.c()).K()).f;
                    Intrinsics.checkNotNullExpressionValue(interstitialHeader2, "interstitialHeader");
                    interstitialHeader2.setText(R.string.quizlet_live_interstitial_teacher_header_text);
                    QTextView interstitialSubText2 = ((N) ((QuizletLiveInterstitialActivity) cVar2.c()).K()).g;
                    Intrinsics.checkNotNullExpressionValue(interstitialSubText2, "interstitialSubText");
                    interstitialSubText2.setText(R.string.quizlet_live_interstitial_teacher_sub_text);
                    AssemblyTextButton btnSecondaryAction3 = ((N) ((QuizletLiveInterstitialActivity) cVar2.c()).K()).c;
                    Intrinsics.checkNotNullExpressionValue(btnSecondaryAction3, "btnSecondaryAction");
                    btnSecondaryAction3.setText(R.string.secondary_action_teacher_text);
                    break;
                }
                break;
        }
    }
}
