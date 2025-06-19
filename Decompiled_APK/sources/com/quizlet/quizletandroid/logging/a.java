package com.quizlet.quizletandroid.logging;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.accessibility.AccessibilityManager;
import androidx.core.app.NotificationManagerCompat;
import androidx.glance.appwidget.protobuf.Z;
import androidx.work.impl.A;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.firebase.analytics.FirebaseAnalytics;
import com.quizlet.analytics.marketing.e;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.NotificationDeviceStatus;
import com.quizlet.eventlogger.model.NotificationDeviceStatusLog;
import com.quizlet.infra.legacysyncengine.managers.d;
import com.quizlet.quizletandroid.QuizletApplication;
import com.quizlet.quizletandroid.lib.c;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public final /* synthetic */ b j;
    public final /* synthetic */ QuizletApplication k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(b bVar, QuizletApplication quizletApplication, h hVar) {
        super(2, hVar);
        this.j = bVar;
        this.k = quizletApplication;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Map<String, Boolean> mapC;
        String strWriteValueAsString;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        b bVar = this.j;
        SharedPreferences sharedPreferences = new c(bVar.b).a;
        boolean z = sharedPreferences.getBoolean("PREFS_IS_FIRST_APP_OPEN", true);
        com.quizlet.data.repository.user.a aVar2 = bVar.d;
        EventLogger eventLogger = bVar.c;
        if (z) {
            eventLogger.m(bVar.a());
            Bundle bundle = new Bundle();
            bundle.putString("clientId", ((com.google.android.gms.analytics.c) aVar2.c).a());
            String languageTag = Locale.getDefault().toLanguageTag();
            Intrinsics.checkNotNullExpressionValue(languageTag, "toLanguageTag(...)");
            String lowerCase = languageTag.toLowerCase(Locale.ROOT);
            Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
            bundle.putString("locale", lowerCase);
            timber.log.c.a.g("Logging firstOpen event w/ bundle %s", bundle);
            ((FirebaseAnalytics) aVar2.d).a(bundle, "firstOpen");
            assistantMode.refactored.a.p(sharedPreferences, "PREFS_IS_FIRST_APP_OPEN", false);
        }
        eventLogger.c(bVar.a());
        ((d) aVar2.b).a().i(new e(aVar2, 21), new com.quizlet.billing.manager.d(timber.log.c.a, 6));
        Context context = bVar.b;
        if (context.getResources().getConfiguration().keyboard == 2) {
            eventLogger.I("launch_with_hard_keyboard");
        }
        com.quizlet.data.interactor.school.b bVar2 = bVar.e;
        int[] iArr = {-1, 4, 32, 16, 2, 1, 8};
        int i = 0;
        for (int i2 = 7; i < i2; i2 = 7) {
            int i3 = iArr[i];
            List<AccessibilityServiceInfo> enabledAccessibilityServiceList = ((AccessibilityManager) bVar2.b).getEnabledAccessibilityServiceList(i3);
            if (enabledAccessibilityServiceList != null) {
                for (AccessibilityServiceInfo accessibilityServiceInfo : enabledAccessibilityServiceList) {
                    EventLogger eventLogger2 = (EventLogger) bVar2.c;
                    if (i3 == -1) {
                        eventLogger2.I("launch_with_all_mask_accessibility_enabled");
                    } else if (i3 == 4) {
                        eventLogger2.I("launch_with_audible_accessibility_enabled");
                    } else if (i3 == 8) {
                        eventLogger2.I("launch_with_visual_accessibility_enabled");
                    } else if (i3 == 16) {
                        eventLogger2.I("launch_with_generic_accessibility_enabled");
                    } else if (i3 == 32) {
                        eventLogger2.I("launch_with_braille_accessibility_enabled");
                    } else if (i3 == 1) {
                        eventLogger2.I("launch_with_spoken_accessibility_enabled");
                    } else if (i3 == 2) {
                        eventLogger2.I("launch_with_haptic_accessibility_enabled");
                    }
                }
            }
            i++;
        }
        boolean zAreNotificationsEnabled = NotificationManagerCompat.from(context).areNotificationsEnabled();
        NotificationDeviceStatusLog.StatusExtraInfo statusExtraInfo = new NotificationDeviceStatusLog.StatusExtraInfo();
        try {
            List<NotificationChannel> notificationChannels = ((NotificationManager) bVar.g.c).getNotificationChannels();
            Intrinsics.checkNotNullExpressionValue(notificationChannels, "getNotificationChannels(...)");
            int iA = U.a(kotlin.collections.C.q(notificationChannels, 10));
            if (iA < 16) {
                iA = 16;
            }
            mapC = new LinkedHashMap<>(iA);
            for (Object obj2 : notificationChannels) {
                String id = ((NotificationChannel) obj2).getId();
                Intrinsics.checkNotNullExpressionValue(id, "getId(...)");
                mapC.put(id, Boolean.valueOf(((NotificationChannel) obj2).getImportance() != 0));
            }
        } catch (Exception e) {
            timber.log.c.a.f(e, "Error retrieving notificationChannels from service NotificationManager", new Object[0]);
            mapC = V.c();
        }
        statusExtraInfo.setChannels(mapC);
        try {
            strWriteValueAsString = bVar.h.writeValueAsString(statusExtraInfo);
        } catch (JsonProcessingException e2) {
            timber.log.c.a.f(e2, "Error while building extra info for notification status logging", new Object[0]);
            strWriteValueAsString = null;
        }
        NotificationDeviceStatus notificationDeviceStatus = bVar.f;
        Boolean notificationDeviceStatus2 = notificationDeviceStatus.getNotificationDeviceStatus();
        String notificationChannelsStatus = notificationDeviceStatus.getNotificationChannelsStatus();
        if (notificationDeviceStatus2 == null || !notificationDeviceStatus2.equals(Boolean.valueOf(zAreNotificationsEnabled)) || (notificationChannelsStatus != null && !notificationChannelsStatus.equals(strWriteValueAsString))) {
            notificationDeviceStatus.setNotificationDeviceStatus(zAreNotificationsEnabled);
            notificationDeviceStatus.setNotificationChannelsStatus(strWriteValueAsString);
            eventLogger.s(strWriteValueAsString, zAreNotificationsEnabled);
        }
        QuizletApplication quizletApplication = this.k;
        com.quizlet.quizletandroid.lib.b bVar3 = new com.quizlet.quizletandroid.lib.b(quizletApplication);
        SharedPreferences sharedPreferences2 = bVar3.a;
        if (!sharedPreferences2.contains("PREFS_VERSION_CODE") || sharedPreferences2.getInt("PREFS_VERSION_CODE", 2601637) != 2601637) {
            quizletApplication.l = (AtomicReference) new io.reactivex.rxjava3.internal.operators.completable.c(new A(10, quizletApplication, bVar3), 4).h(io.reactivex.rxjava3.schedulers.e.c).e();
        }
        return Unit.a;
    }
}
