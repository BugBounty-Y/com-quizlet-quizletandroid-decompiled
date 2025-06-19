package com.quizlet.features.practicetest.navigation;

import androidx.compose.animation.C0292t;
import androidx.compose.animation.V;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.K0;
import androidx.compose.animation.core.L0;
import androidx.compose.ui.semantics.t;
import androidx.compose.ui.semantics.v;
import androidx.navigation.C1290l;
import androidx.navigation.L;
import androidx.navigation.Y;
import assistantMode.enums.k;
import com.comscore.streaming.EventType;
import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.studiablemodels.StudiableAudio;
import java.util.Locale;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int i = 4;
        int i2 = 0;
        int i3 = 1;
        switch (this.a) {
            case 0:
                L navigate = (L) obj;
                Intrinsics.checkNotNullParameter(navigate, "$this$navigate");
                navigate.b = true;
                L.b(navigate);
                break;
            case 1:
                Y popUpTo = (Y) obj;
                Intrinsics.checkNotNullParameter(popUpTo, "$this$popUpTo");
                popUpTo.a = true;
                break;
            case 2:
                L navOptions = (L) obj;
                Intrinsics.checkNotNullParameter(navOptions, "$this$navOptions");
                navOptions.b = true;
                break;
            case 3:
                L navigate2 = (L) obj;
                Intrinsics.checkNotNullParameter(navigate2, "$this$navigate");
                navigate2.b = true;
                break;
            case 4:
                L navOptions2 = (L) obj;
                Intrinsics.checkNotNullParameter(navOptions2, "$this$navOptions");
                navOptions2.b = true;
                break;
            case 5:
                L navigate3 = (L) obj;
                Intrinsics.checkNotNullParameter(navigate3, "$this$navigate");
                navigate3.b = true;
                break;
            case 6:
                L navOptions3 = (L) obj;
                Intrinsics.checkNotNullParameter(navOptions3, "$this$navOptions");
                navOptions3.b = true;
                L.b(navOptions3);
                break;
            case 7:
                C0292t AnimatedContent = (C0292t) obj;
                Intrinsics.checkNotNullParameter(AnimatedContent, "$this$AnimatedContent");
                com.quizlet.themes.a aVar = com.quizlet.themes.a.c;
                K0 k0R = AbstractC0240f.r(250, 0, aVar.c(), 2);
                androidx.camera.lifecycle.f fVar = new androidx.camera.lifecycle.f(new com.quizlet.features.practicetest.takingtest.i(AnimatedContent, i2), i);
                L0 l0 = V.a;
                break;
            case 8:
                v semantics = (v) obj;
                Intrinsics.checkNotNullParameter(semantics, "$this$semantics");
                t.i(semantics, "questionnaire_scaffold");
                break;
            case 9:
                v semantics2 = (v) obj;
                Intrinsics.checkNotNullParameter(semantics2, "$this$semantics");
                t.i(semantics2, "questionnaire_intro_screen");
                break;
            case 10:
                v semantics3 = (v) obj;
                Intrinsics.checkNotNullParameter(semantics3, "$this$semantics");
                t.i(semantics3, "questionnaire_exams_screen");
                break;
            case 11:
                v semantics4 = (v) obj;
                Intrinsics.checkNotNullParameter(semantics4, "$this$semantics");
                t.i(semantics4, "questionnaire_school_course_screen");
                break;
            case 12:
                v semantics5 = (v) obj;
                Intrinsics.checkNotNullParameter(semantics5, "$this$semantics");
                t.i(semantics5, "questionnaire_toolbar");
                break;
            case 13:
                v semantics6 = (v) obj;
                Intrinsics.checkNotNullParameter(semantics6, "$this$semantics");
                t.i(semantics6, "questionnaire_nav_host");
                break;
            case 14:
                k it2 = (k) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                Intrinsics.checkNotNullParameter(it2, "<this>");
                int iOrdinal = it2.ordinal();
                String lowerCase = (iOrdinal != 0 ? iOrdinal != 2 ? iOrdinal != 4 ? iOrdinal != 10 ? com.quizlet.features.questiontypes.data.c.b : com.quizlet.features.questiontypes.data.c.b : com.quizlet.features.questiontypes.data.c.d : com.quizlet.features.questiontypes.data.c.a : com.quizlet.features.questiontypes.data.c.c).toString().toLowerCase(Locale.ROOT);
                Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
                break;
            case 15:
                Intrinsics.checkNotNullParameter((StudiableAudio) obj, "it");
                break;
            case 16:
                Intrinsics.checkNotNullParameter((String) obj, "it");
                break;
            case 17:
                AndroidEventLog logUserActionAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent.setUserAction("set_page_progress_reset_close");
                break;
            case 18:
                AndroidEventLog logUserActionAndroidEvent2 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent2, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent2.setUserAction("set_page_progress_reset_open");
                break;
            case 19:
                AndroidEventLog logUserActionAndroidEvent3 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent3, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent3.setUserAction("set_page_progress_reset");
                break;
            case 20:
                com.quizlet.features.setpage.termlist.data.k it3 = (com.quizlet.features.setpage.termlist.data.k) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                break;
            case 21:
                Throwable error = (Throwable) obj;
                Intrinsics.checkNotNullParameter(error, "error");
                timber.log.c.a.d("Unable to load set page data " + error, new Object[0]);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                Throwable it4 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                timber.log.c.a.f(it4, "Error showing ads", new Object[0]);
                break;
            case EventType.AUDIO /* 23 */:
                Intrinsics.checkNotNullParameter((com.quizlet.themes.nighttheme.a) obj, "it");
                break;
            case EventType.VIDEO /* 24 */:
                Intrinsics.checkNotNullParameter((String) obj, "it");
                break;
            case EventType.SUBS /* 25 */:
                Intrinsics.checkNotNullParameter((String) obj, "it");
                break;
            case EventType.CDN /* 26 */:
                C1290l navArgument = (C1290l) obj;
                Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                break;
            case 27:
                C1290l navArgument2 = (C1290l) obj;
                Intrinsics.checkNotNullParameter(navArgument2, "$this$navArgument");
                break;
            case 28:
                AndroidEventLog logUserActionAndroidEvent4 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent4, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent4.setUserAction("tapped_search_from_subject");
                break;
            default:
                AndroidEventLog logUserActionAndroidEvent5 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent5, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent5.setUserAction("tapped_create_from_subject");
                break;
        }
        return Unit.a;
    }
}
