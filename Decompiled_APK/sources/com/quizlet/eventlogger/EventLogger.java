package com.quizlet.eventlogger;

import assistantMode.enums.m;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.eventlogger.features.pushnotifications.FirebaseMessagePayload;
import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.eventlogger.model.EmailTrackingEventLog;
import com.quizlet.eventlogger.model.EventLog;
import com.quizlet.eventlogger.model.NavigationEventLog;
import com.quizlet.eventlogger.model.NotificationDeviceStatusLog;
import com.quizlet.eventlogger.model.PushNotificationsLog;
import com.quizlet.eventlogger.model.ShareEventLog;
import com.quizlet.eventlogger.model.ViewsEventLog;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class EventLogger {
    public static String a;
    public static String b;
    private final EventLogBuilder mBuilder;
    private final String versionName;

    @Retention(RetentionPolicy.SOURCE)
    public @interface AuthProvider {
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface ClassJoined {
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface ErrorClassCreation {
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface NextAction {
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface QuizletLive {
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface UserAccount {
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface UserAction {
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface UserActionAddClassSet {
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface UserActionClass {
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface UserActionFlashcards {
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface UserActionLearningAssistant {
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface UserActionOnboarding {
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface UserActionScanDocument {
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface UserActionSearch {
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface UserActionUpgrade {
    }

    public EventLogger(EventLogBuilder eventLogBuilder, String str) {
        this.mBuilder = eventLogBuilder;
        this.versionName = str;
    }

    public final void A(String str, long j, boolean z) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("leave_screen", str);
        androidEventLogD.setVisitDurationMs(Long.valueOf(j));
        androidEventLogD.setPreviousScreenName(b);
        androidEventLogD.setLandscape(Boolean.valueOf(z));
        b = str;
        a = null;
        this.mBuilder.j(androidEventLogD);
    }

    public final void B(String str, boolean z) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("visit_screen", str);
        androidEventLogD.setPreviousScreenName(b);
        androidEventLogD.setLandscape(Boolean.valueOf(z));
        a = str;
        this.mBuilder.j(androidEventLogD);
    }

    public final void C(String sharedUrl) {
        EventLogBuilder eventLogBuilder = this.mBuilder;
        ShareEventLog.b.getClass();
        Intrinsics.checkNotNullParameter(sharedUrl, "sharedUrl");
        ShareEventLog shareEventLog = new ShareEventLog();
        shareEventLog.setAction("user_clicked_to_share_set");
        shareEventLog.getPayload().setShareUrl(sharedUrl);
        eventLogBuilder.j(shareEventLog);
    }

    public final void D(String str) {
        AndroidEventLog androidEventLogC = AndroidEventLog.c("user_action_subscription");
        androidEventLogC.setUserAction(str);
        this.mBuilder.j(androidEventLogC);
    }

    public final void E(String str, String str2) {
        AndroidEventLog androidEventLogC = AndroidEventLog.c("user_action_subscription");
        androidEventLogC.setUserAction(str);
        androidEventLogC.setMessage(str2);
        this.mBuilder.j(androidEventLogC);
    }

    public final void F(String str, String str2) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("user_action_subscription", str2);
        androidEventLogD.setUserAction(str);
        androidEventLogD.setMessage(null);
        this.mBuilder.j(androidEventLogD);
    }

    public final void G(String str, String str2) {
        AndroidEventLog androidEventLogC = AndroidEventLog.c("user_action_subscription");
        androidEventLogC.setUserAction(str);
        androidEventLogC.setMessage("Target package: ".concat(str2));
        this.mBuilder.j(androidEventLogC);
    }

    public final void H(int i, String str) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("user_action", a);
        androidEventLogD.setUserAction(str);
        androidEventLogD.setDepth(Integer.valueOf(i));
        this.mBuilder.j(androidEventLogD);
    }

    public final void I(String str) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("user_action", a);
        androidEventLogD.setUserAction(str);
        this.mBuilder.j(androidEventLogD);
    }

    public final void J(int i, long j) {
        EventLogBuilder eventLogBuilder = this.mBuilder;
        String versionName = this.versionName;
        ViewsEventLog.b.getClass();
        Intrinsics.checkNotNullParameter(versionName, "versionName");
        ViewsEventLog viewsEventLogA = ViewsEventLog.Companion.a(i, 0L, 0L, versionName);
        viewsEventLogA.getPayload().setServerModelId(j > 0 ? Long.valueOf(j) : null);
        viewsEventLogA.getPayload().setClientModelId(j < 0 ? Long.valueOf(j) : null);
        eventLogBuilder.j(viewsEventLogA);
    }

    public final void K(long j, long j2, int i) {
        EventLogBuilder eventLogBuilder = this.mBuilder;
        Long lValueOf = j > 0 ? Long.valueOf(j) : null;
        String str = this.versionName;
        ViewsEventLog.b.getClass();
        eventLogBuilder.j(ViewsEventLog.Companion.a(i, lValueOf, j2, str));
    }

    public final void a(int i) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("ocr_image_upload_success", a);
        androidEventLogD.setSize(Integer.valueOf(i));
        this.mBuilder.j(androidEventLogD);
    }

    public final void b(Integer num, String str) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("user_action_add_class_set", a);
        androidEventLogD.setUserAction(str);
        if (num != null) {
            androidEventLogD.setSize(num);
        }
        this.mBuilder.j(androidEventLogD);
    }

    public final void c(int i) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("app_launch", a);
        androidEventLogD.setGmsVersion(Integer.valueOf(i));
        this.mBuilder.j(androidEventLogD);
    }

    public final void d(String str, boolean z) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("attempt_authentication", a);
        androidEventLogD.setAuthenticationProvider(str);
        androidEventLogD.setSignUp(Boolean.valueOf(z));
        this.mBuilder.j(androidEventLogD);
    }

    public final void e(String str, boolean z) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("authentication_birthday_request", a);
        androidEventLogD.setAuthenticationProvider(str);
        androidEventLogD.setSignUp(Boolean.valueOf(z));
        this.mBuilder.j(androidEventLogD);
    }

    public final void f(String str, boolean z) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("authenticated", a);
        androidEventLogD.setAuthenticationProvider(str);
        androidEventLogD.setSignUp(Boolean.valueOf(z));
        this.mBuilder.j(androidEventLogD);
    }

    public final void g(DBUser dBUser, String str, String str2) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("user_action_class", a);
        androidEventLogD.setUserAction(str);
        if (dBUser != null) {
            androidEventLogD.setUserId(Long.valueOf(dBUser.getId()));
            androidEventLogD.setUsername(dBUser.getUsername());
        }
        if (str2 != null) {
            androidEventLogD.setMessage(str2);
        }
        this.mBuilder.j(androidEventLogD);
    }

    public String getVersionName() {
        return this.versionName;
    }

    public final void h(boolean z) {
        this.mBuilder.j(AndroidEventLog.d(z ? "connection_now_online" : "connection_now_offline", a));
    }

    public final void i(EventLog.DiskSpace diskSpace, int i) {
        AndroidEventLog androidEventLogC = AndroidEventLog.c(diskSpace.getValue());
        androidEventLogC.setMessage(Integer.toString(i));
        this.mBuilder.j(androidEventLogC);
    }

    public final void j(String emailAddress, String mailgunTag, String str, Long l, String fullUrl, String activityName) {
        EventLog.a.getClass();
        Intrinsics.checkNotNullParameter(emailAddress, "emailAddress");
        Intrinsics.checkNotNullParameter(mailgunTag, "mailgunTag");
        Intrinsics.checkNotNullParameter(fullUrl, "fullUrl");
        Intrinsics.checkNotNullParameter(activityName, "activityName");
        EmailTrackingEventLog emailTrackingEventLog = new EmailTrackingEventLog();
        emailTrackingEventLog.setAction("clicked");
        emailTrackingEventLog.getPayload().setEmailAddress(emailAddress);
        emailTrackingEventLog.getPayload().setMailgunTag(mailgunTag);
        emailTrackingEventLog.getPayload().setSourceKey(l);
        emailTrackingEventLog.getPayload().setSourceType(str);
        emailTrackingEventLog.getPayload().setName(activityName);
        emailTrackingEventLog.getPayload().setPage(fullUrl);
        this.mBuilder.j(emailTrackingEventLog);
    }

    public final void k(String str) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("error", a);
        androidEventLogD.setMessage(str);
        this.mBuilder.j(androidEventLogD);
    }

    public final void l(EventLog eventLog) {
        this.mBuilder.j(eventLog);
    }

    public final void m(int i) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("first_app_launch", a);
        androidEventLogD.setGmsVersion(Integer.valueOf(i));
        this.mBuilder.j(androidEventLogD);
    }

    public final void n(String str, Integer num, Integer num2, Boolean bool, Boolean bool2, m mVar) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("user_action_flashcards", a);
        androidEventLogD.setUserActionFlashcards(str);
        if (num != null) {
            androidEventLogD.setDepth(num);
        }
        if (num2 != null) {
            androidEventLogD.setSize(num2);
        }
        if (bool != null) {
            androidEventLogD.setEnabled(bool);
        }
        if (mVar != null) {
            androidEventLogD.setPromptSide(mVar.a);
        }
        if (bool2 != null) {
            androidEventLogD.setSorting(bool2.booleanValue() ? "enabled" : "disabled");
        }
        this.mBuilder.j(androidEventLogD);
    }

    public final void o(com.quizlet.utmhelper.a utmParams, Integer num, Long l, String sharedUrl, String str) {
        EventLogBuilder eventLogBuilder = this.mBuilder;
        ShareEventLog.b.getClass();
        Intrinsics.checkNotNullParameter(sharedUrl, "sharedUrl");
        Intrinsics.checkNotNullParameter(utmParams, "utmParams");
        ShareEventLog shareEventLog = new ShareEventLog();
        shareEventLog.setAction("inbound");
        shareEventLog.getPayload().setSharerUserId(utmParams.a);
        shareEventLog.getPayload().setServerModelId(l);
        shareEventLog.getPayload().setServerModelUuid(str);
        shareEventLog.getPayload().setModelType(num);
        shareEventLog.getPayload().setShareUrl(sharedUrl);
        shareEventLog.getPayload().setUtmCampaign(utmParams.b);
        shareEventLog.getPayload().setUtmMedium(utmParams.c);
        shareEventLog.getPayload().setUtmSource(utmParams.d);
        eventLogBuilder.j(shareEventLog);
    }

    public final void p(long j) {
        String str = a;
        AndroidEventLog.b.getClass();
        AndroidEventLog androidEventLogA = AndroidEventLog.Companion.a(4, j, 0L, "user_action_class", str);
        androidEventLogA.setUserAction("class_joined");
        this.mBuilder.j(androidEventLogA);
    }

    public final void q(String str) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("user_action_learning_assistant", a);
        androidEventLogD.setUserAction(str);
        this.mBuilder.j(androidEventLogD);
    }

    public final void r(String screenName, String clickName, String str, boolean z) {
        NavigationEventLog.b.getClass();
        Intrinsics.checkNotNullParameter(screenName, "screenName");
        Intrinsics.checkNotNullParameter(clickName, "clickName");
        this.mBuilder.j(NavigationEventLog.Companion.a(z, screenName, clickName, str, null));
    }

    public final void s(String str, boolean z) {
        NotificationDeviceStatusLog.b.getClass();
        NotificationDeviceStatusLog notificationDeviceStatusLog = new NotificationDeviceStatusLog();
        notificationDeviceStatusLog.setAction("status_changed");
        if (z) {
            notificationDeviceStatusLog.getPayload().setStatus(3);
        } else {
            notificationDeviceStatusLog.getPayload().setStatus(2);
        }
        notificationDeviceStatusLog.getPayload().setExtraInfo(str);
        this.mBuilder.j(notificationDeviceStatusLog);
    }

    public final void t(String str, Long l, com.quizlet.utmhelper.a aVar) {
        EventLogBuilder eventLogBuilder = this.mBuilder;
        ShareEventLog.b.getClass();
        eventLogBuilder.j(ShareEventLog.Companion.a(aVar, 3, l, str, null));
    }

    public final void u(String sharedUrl, Long l, String str, Integer num, com.quizlet.utmhelper.a utmParams, String str2) {
        EventLogBuilder eventLogBuilder = this.mBuilder;
        ShareEventLog.b.getClass();
        Intrinsics.checkNotNullParameter(sharedUrl, "sharedUrl");
        Intrinsics.checkNotNullParameter(utmParams, "utmParams");
        ShareEventLog shareEventLogA = ShareEventLog.Companion.a(utmParams, num, l, sharedUrl, str);
        shareEventLogA.getPayload().setNormalizedSource(str2);
        eventLogBuilder.j(shareEventLogA);
    }

    public final void v(EventLog eventLog) {
        this.mBuilder.j(eventLog);
    }

    public final void w(FirebaseMessagePayload messagePayload) {
        PushNotificationsLog.b.getClass();
        Intrinsics.checkNotNullParameter("open", "action");
        Intrinsics.checkNotNullParameter(messagePayload, "messagePayload");
        PushNotificationsLog pushNotificationsLog = new PushNotificationsLog();
        pushNotificationsLog.setAction("open");
        pushNotificationsLog.getPayload().setMessageId(messagePayload.getMessageId());
        if (messagePayload.getType() != null) {
            pushNotificationsLog.getPayload().setNotificationType(Integer.valueOf(messagePayload.getType().a()));
        }
        if (messagePayload.getSetId() != null) {
            pushNotificationsLog.getPayload().setModelType(1);
            pushNotificationsLog.getPayload().setServerModelId(messagePayload.getSetId());
        } else if (messagePayload.getFolderId() != null) {
            pushNotificationsLog.getPayload().setModelType(3);
            pushNotificationsLog.getPayload().setServerModelId(messagePayload.getFolderId());
        }
        this.mBuilder.j(pushNotificationsLog);
    }

    public final void x(String str) {
        this.mBuilder.j(AndroidEventLog.c(str));
    }

    public final void y(int i) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("user_action", a);
        androidEventLogD.setUserAction("ocr_tap_add_card");
        androidEventLogD.setSize(Integer.valueOf(i));
        this.mBuilder.j(androidEventLogD);
    }

    public final void z(String str) {
        AndroidEventLog androidEventLogD = AndroidEventLog.d("user_action", a);
        androidEventLogD.setUserAction(str);
        this.mBuilder.j(androidEventLogD);
    }
}
