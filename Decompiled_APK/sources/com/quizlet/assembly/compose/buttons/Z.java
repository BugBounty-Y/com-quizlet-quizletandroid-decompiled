package com.quizlet.assembly.compose.buttons;

import android.view.MotionEvent;
import com.comscore.streaming.EventType;
import com.quizlet.data.model.M1;
import com.quizlet.data.model.RecommendedStudyMaterial;
import com.quizlet.diagrams.DiagramWebView;
import com.quizlet.eventlogger.features.achievements.AchievementsEventLog;
import com.quizlet.eventlogger.features.autolaunch.AutoLaunchEventLog;
import com.quizlet.eventlogger.features.home.HomeEdgyEventLogger;
import com.quizlet.eventlogger.features.pushnotifications.PushNotificationLogger;
import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.eventlogger.model.LibraryEventLog;
import com.quizlet.eventlogger.model.NotesEventLog;
import com.quizlet.eventlogger.model.StudyFunnelEventLog;
import com.quizlet.eventlogger.model.UniversalUploadFlowEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class Z implements Function1 {
    public final /* synthetic */ int a;

    public /* synthetic */ Z(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        RecommendedStudyMaterial recommendedStudyMaterial;
        boolean z = false;
        switch (this.a) {
            case 0:
                androidx.compose.ui.graphics.drawscope.d LinearProgressIndicator = (androidx.compose.ui.graphics.drawscope.d) obj;
                Intrinsics.checkNotNullParameter(LinearProgressIndicator, "$this$LinearProgressIndicator");
                break;
            case 1:
                Intrinsics.checkNotNullParameter((String) obj, "it");
                break;
            case 2:
                M1 it2 = (M1) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                recommendedStudyMaterial = it2 instanceof RecommendedStudyMaterial ? (RecommendedStudyMaterial) it2 : null;
                if (recommendedStudyMaterial != null && recommendedStudyMaterial.d) {
                    z = true;
                }
                break;
            case 3:
                M1 it3 = (M1) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                recommendedStudyMaterial = it3 instanceof RecommendedStudyMaterial ? (RecommendedStudyMaterial) it3 : null;
                if (recommendedStudyMaterial != null && recommendedStudyMaterial.d) {
                    z = true;
                }
                break;
            case 4:
                Intrinsics.checkNotNullParameter((DiagramWebView) obj, "it");
                break;
            case 5:
                AndroidEventLog logAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent, "$this$logAndroidEvent");
                break;
            case 6:
                Intrinsics.checkNotNullParameter((AndroidEventLog) obj, "<this>");
                break;
            case 7:
                Intrinsics.checkNotNullParameter((AchievementsEventLog.Payload) obj, "<this>");
                break;
            case 8:
                Intrinsics.checkNotNullParameter((AndroidEventLog) obj, "<this>");
                break;
            case 9:
                AndroidEventLog logAndroidEvent2 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent2, "$this$logAndroidEvent");
                break;
            case 10:
                AndroidEventLog logAndroidEvent3 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent3, "$this$logAndroidEvent");
                break;
            case 11:
                AndroidEventLog logAndroidEvent4 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent4, "$this$logAndroidEvent");
                break;
            case 12:
                Intrinsics.checkNotNullParameter((AutoLaunchEventLog.Payload) obj, "<this>");
                break;
            case 13:
                AndroidEventLog logUserActionAndroidEvent = (AndroidEventLog) obj;
                int i = HomeEdgyEventLogger.a;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent.setUserAction("open_edgy_modal_course_overview_lih");
                break;
            case 14:
                com.quizlet.studiablemodels.assistantMode.a it4 = (com.quizlet.studiablemodels.assistantMode.a) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                break;
            case 15:
                com.quizlet.studiablemodels.assistantMode.a it5 = (com.quizlet.studiablemodels.assistantMode.a) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                break;
            case 16:
                AndroidEventLog logUserActionAndroidEvent2 = (AndroidEventLog) obj;
                int i2 = PushNotificationLogger.a;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent2, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent2.setUserAction("push_primer_seen");
                break;
            case 17:
                AndroidEventLog logUserActionAndroidEvent3 = (AndroidEventLog) obj;
                int i3 = PushNotificationLogger.a;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent3, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent3.setUserAction("push_notification_system_prompt_seen");
                break;
            case 18:
                AndroidEventLog logUserActionAndroidEvent4 = (AndroidEventLog) obj;
                int i4 = PushNotificationLogger.a;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent4, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent4.setUserAction("push_notification_permission_denied");
                break;
            case 19:
                AndroidEventLog logUserActionAndroidEvent5 = (AndroidEventLog) obj;
                int i5 = PushNotificationLogger.a;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent5, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent5.setUserAction("push_notification_permission_granted");
                break;
            case 20:
                AndroidEventLog logUserActionAndroidEvent6 = (AndroidEventLog) obj;
                int i6 = PushNotificationLogger.a;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent6, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent6.setUserAction("push_primer_accepted");
                break;
            case 21:
                Intrinsics.checkNotNullParameter((StudyFunnelEventLog) obj, "<this>");
                break;
            case EventType.WINDOW_STATE /* 22 */:
                Intrinsics.checkNotNullParameter((LibraryEventLog.Payload) obj, "<this>");
                break;
            case EventType.AUDIO /* 23 */:
                Intrinsics.checkNotNullParameter((NotesEventLog.Payload) obj, "<this>");
                break;
            case EventType.VIDEO /* 24 */:
                Intrinsics.checkNotNullParameter((UniversalUploadFlowEventLog.Payload) obj, "<this>");
                break;
            case EventType.SUBS /* 25 */:
                Intrinsics.checkNotNullParameter((String) obj, "it");
                break;
            case EventType.CDN /* 26 */:
                String it6 = (String) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                break;
            case 27:
                Intrinsics.checkNotNullParameter((MotionEvent) obj, "it");
                break;
            case 28:
                Intrinsics.checkNotNullParameter((String) obj, "it");
                break;
            default:
                Intrinsics.checkNotNullParameter((String) obj, "it");
                break;
        }
        return Unit.a;
    }
}
