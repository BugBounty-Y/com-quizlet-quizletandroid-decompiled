package com.quizlet.quizletandroid.ui.login;

import androidx.navigation.C1290l;
import androidx.navigation.L;
import androidx.navigation.S;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3344h;
import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.generated.enums.A1;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4761c;
import java.util.Locale;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class z implements Function1 {
    public final /* synthetic */ int a;

    public /* synthetic */ z(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                AndroidEventLog logUserActionAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent.setUserAction("login_screen_email_button_tapped");
                break;
            case 1:
                AndroidEventLog logUserActionAndroidEvent2 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent2, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent2.setUserAction("intro_screen_email_signup_button_tapped");
                break;
            case 2:
                AndroidEventLog logUserActionAndroidEvent3 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent3, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent3.setUserAction("login_screen_google_button_tapped");
                break;
            case 3:
                AndroidEventLog logUserActionAndroidEvent4 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent4, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent4.setUserAction("intro_screen_google_button_tapped");
                break;
            case 4:
                AndroidEventLog logUserActionAndroidEvent5 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent5, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent5.setUserAction("intro_screen_email_login_button_tapped");
                break;
            case 5:
                AndroidEventLog logUserActionAndroidEvent6 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent6, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent6.setUserAction("login_screen_facebook_button_tapped");
                break;
            case 6:
                AndroidEventLog logUserActionAndroidEvent7 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent7, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent7.setAction("set_creation_privo_modal_opened");
                break;
            case 7:
                AndroidEventLog logUserActionAndroidEvent8 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent8, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent8.setAction("set_creation_privo_modal_resend_email_clicked");
                logUserActionAndroidEvent8.setUserAction("set_creation_privo_modal_resend_email_clicked");
                break;
            case 8:
                AndroidEventLog logUserActionAndroidEvent9 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent9, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent9.setAction("set_creation_privo_modal_closed");
                logUserActionAndroidEvent9.setUserAction("set_creation_privo_modal_closed");
                break;
            case 9:
                Throwable error = (Throwable) obj;
                Intrinsics.checkNotNullParameter(error, "error");
                timber.log.c.a.e(error);
                break;
            case 10:
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p pVar = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p) obj;
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o oVar = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(true, true);
                pVar.getClass();
                Intrinsics.checkNotNullParameter(oVar, "<set-?>");
                pVar.g = oVar;
                break;
            case 11:
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p pVar2 = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p) obj;
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o oVar2 = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(true, true);
                pVar2.getClass();
                Intrinsics.checkNotNullParameter(oVar2, "<set-?>");
                pVar2.e = oVar2;
                break;
            case 12:
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.f it2 = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.f) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                break;
            case 13:
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.h it3 = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.h) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                break;
            case 14:
                L navigate = (L) obj;
                Intrinsics.checkNotNullParameter(navigate, "$this$navigate");
                navigate.b = true;
                break;
            case 15:
                C1290l navArgument = (C1290l) obj;
                Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                navArgument.b(S.b);
                navArgument.a.a = false;
                navArgument.a(Integer.valueOf(A1.LEARNING_ASSISTANT.a()));
                break;
            case 16:
                assistantMode.enums.k it4 = (assistantMode.enums.k) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                Intrinsics.checkNotNullParameter(it4, "<this>");
                int iOrdinal = it4.ordinal();
                String lowerCase = (iOrdinal != 0 ? iOrdinal != 2 ? iOrdinal != 4 ? iOrdinal != 10 ? com.quizlet.features.questiontypes.data.c.b : com.quizlet.features.questiontypes.data.c.b : com.quizlet.features.questiontypes.data.c.d : com.quizlet.features.questiontypes.data.c.a : com.quizlet.features.questiontypes.data.c.c).toString().toLowerCase(Locale.ROOT);
                Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
                break;
            case 17:
                C4761c it5 = (C4761c) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                break;
            case 18:
                androidx.glance.semantics.a semantics = (androidx.glance.semantics.a) obj;
                Intrinsics.checkNotNullParameter(semantics, "$this$semantics");
                AbstractC3344h.c(semantics, "logged_out_image");
                break;
            case 19:
                androidx.glance.semantics.a semantics2 = (androidx.glance.semantics.a) obj;
                Intrinsics.checkNotNullParameter(semantics2, "$this$semantics");
                AbstractC3344h.c(semantics2, "search_button_image");
                break;
            case 20:
                androidx.glance.semantics.a semantics3 = (androidx.glance.semantics.a) obj;
                Intrinsics.checkNotNullParameter(semantics3, "$this$semantics");
                AbstractC3344h.c(semantics3, "active_streak_fire");
                break;
            case 21:
                androidx.glance.semantics.a semantics4 = (androidx.glance.semantics.a) obj;
                Intrinsics.checkNotNullParameter(semantics4, "$this$semantics");
                AbstractC3344h.c(semantics4, "logged_out_container");
                break;
            case EventType.WINDOW_STATE /* 22 */:
                androidx.glance.semantics.a semantics5 = (androidx.glance.semantics.a) obj;
                Intrinsics.checkNotNullParameter(semantics5, "$this$semantics");
                AbstractC3344h.c(semantics5, "set_card");
                break;
            case EventType.AUDIO /* 23 */:
                androidx.glance.semantics.a semantics6 = (androidx.glance.semantics.a) obj;
                Intrinsics.checkNotNullParameter(semantics6, "$this$semantics");
                AbstractC3344h.c(semantics6, "widget_body");
                break;
            case EventType.VIDEO /* 24 */:
                androidx.glance.semantics.a semantics7 = (androidx.glance.semantics.a) obj;
                Intrinsics.checkNotNullParameter(semantics7, "$this$semantics");
                AbstractC3344h.c(semantics7, "background_image");
                break;
            case EventType.SUBS /* 25 */:
                androidx.glance.semantics.a semantics8 = (androidx.glance.semantics.a) obj;
                Intrinsics.checkNotNullParameter(semantics8, "$this$semantics");
                AbstractC3344h.c(semantics8, "search_button");
                break;
            case EventType.CDN /* 26 */:
                androidx.glance.semantics.a semantics9 = (androidx.glance.semantics.a) obj;
                Intrinsics.checkNotNullParameter(semantics9, "$this$semantics");
                AbstractC3344h.c(semantics9, "recent_sets");
                break;
            case 27:
                androidx.glance.semantics.a semantics10 = (androidx.glance.semantics.a) obj;
                Intrinsics.checkNotNullParameter(semantics10, "$this$semantics");
                AbstractC3344h.c(semantics10, "most_recent_set");
                break;
            case 28:
                androidx.glance.semantics.a semantics11 = (androidx.glance.semantics.a) obj;
                Intrinsics.checkNotNullParameter(semantics11, "$this$semantics");
                AbstractC3344h.c(semantics11, "test");
                break;
            default:
                androidx.glance.semantics.a semantics12 = (androidx.glance.semantics.a) obj;
                Intrinsics.checkNotNullParameter(semantics12, "$this$semantics");
                AbstractC3344h.c(semantics12, "set_card");
                break;
        }
        return Unit.a;
    }
}
