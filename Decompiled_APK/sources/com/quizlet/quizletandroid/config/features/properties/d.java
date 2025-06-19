package com.quizlet.quizletandroid.config.features.properties;

import androidx.navigation.Y;
import com.comscore.streaming.EventType;
import com.quizlet.data.model.EnumC4164s0;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.quizletandroid.ui.library.data.p;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements Function1 {
    public final /* synthetic */ int a;

    public /* synthetic */ d(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                DBUser u = (DBUser) obj;
                Intrinsics.checkNotNullParameter(u, "u");
                break;
            case 1:
                DBUser u2 = (DBUser) obj;
                Intrinsics.checkNotNullParameter(u2, "u");
                break;
            case 2:
                DBUser u3 = (DBUser) obj;
                Intrinsics.checkNotNullParameter(u3, "u");
                break;
            case 3:
                DBUser u4 = (DBUser) obj;
                Intrinsics.checkNotNullParameter(u4, "u");
                String countryCode = u4.getCountryCode();
                if (countryCode == null) {
                }
                break;
            case 4:
                DBUser u5 = (DBUser) obj;
                Intrinsics.checkNotNullParameter(u5, "u");
                break;
            case 5:
                String it2 = (String) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                break;
            case 6:
                String it3 = (String) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                break;
            case 7:
                String it4 = (String) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                break;
            case 8:
                AndroidEventLog logUserActionAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent.setUserAction("tapped_activity_center_card");
                break;
            case 9:
                Intrinsics.checkNotNullParameter((Throwable) obj, "it");
                break;
            case 10:
                Y popUpTo = (Y) obj;
                Intrinsics.checkNotNullParameter(popUpTo, "$this$popUpTo");
                popUpTo.b = true;
                break;
            case 11:
                com.quizlet.library.data.d it5 = (com.quizlet.library.data.d) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                break;
            case 12:
                Intrinsics.checkNotNullParameter((EnumC4164s0) obj, "it");
                break;
            case 13:
                Intrinsics.checkNotNullParameter((String) obj, "<unused var>");
                break;
            case 14:
                ((Long) obj).longValue();
                break;
            case 15:
                ((Long) obj).longValue();
                break;
            case 16:
                Intrinsics.checkNotNullParameter((String) obj, "<unused var>");
                break;
            case 17:
                ((Long) obj).longValue();
                break;
            case 18:
                Intrinsics.checkNotNullParameter((String) obj, "<unused var>");
                break;
            case 19:
                ((Integer) obj).intValue();
                break;
            case 20:
                Intrinsics.checkNotNullParameter((String) obj, "it");
                break;
            case 21:
                Intrinsics.checkNotNullParameter((String) obj, "it");
                break;
            case EventType.WINDOW_STATE /* 22 */:
                Intrinsics.checkNotNullParameter((String) obj, "it");
                break;
            case EventType.AUDIO /* 23 */:
                Intrinsics.checkNotNullParameter((p) obj, "it");
                break;
            case EventType.VIDEO /* 24 */:
                ((Integer) obj).intValue();
                break;
            case EventType.SUBS /* 25 */:
                ((Long) obj).longValue();
                break;
            case EventType.CDN /* 26 */:
                ((Integer) obj).intValue();
                break;
            case 27:
                Intrinsics.checkNotNullParameter((String) obj, "<unused var>");
                break;
            case 28:
                Intrinsics.checkNotNullParameter((p) obj, "it");
                break;
            default:
                AndroidEventLog logUserActionAndroidEvent2 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent2, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent2.setUserAction("signup_screen_email_button_tapped");
                break;
        }
        return Unit.a;
    }
}
