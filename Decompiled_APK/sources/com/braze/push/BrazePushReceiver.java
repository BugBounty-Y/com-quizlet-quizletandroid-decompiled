package com.braze.push;

import android.app.Notification;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.core.app.NotificationManagerCompat;
import androidx.navigation.compose.C1277j;
import com.braze.Braze;
import com.braze.BrazeInternal;
import com.braze.C1481g;
import com.braze.Constants;
import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.models.push.BrazeNotificationPayload;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import com.braze.ui.inappmessage.BrazeInAppMessageManager;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class BrazePushReceiver extends BroadcastReceiver {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handleAdmRegistrationEventIfEnabled$lambda$4(Intent intent) {
            return "Received ADM registration. Message: " + intent;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handleAdmRegistrationEventIfEnabled$lambda$5() {
            return "ADM enabled in braze.xml. Continuing to process ADM registration intent.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handleAdmRegistrationEventIfEnabled$lambda$6() {
            return "ADM not enabled in braze.xml. Ignoring ADM registration intent. Note: you must set com_braze_push_adm_messaging_registration_enabled to true in your braze.xml to enable ADM.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handleAdmRegistrationIntent$lambda$10() {
            return "The ADM registration intent is missing error information, registration id, and unregistration confirmation. Ignoring.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handleAdmRegistrationIntent$lambda$7(String str, String str2) {
            return android.support.v4.media.session.a.m("Error during ADM registration: ", str, " description: ", str2);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handleAdmRegistrationIntent$lambda$8(String str) {
            return AbstractC0147y.d("Registering for ADM messages with registrationId: ", str);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handleAdmRegistrationIntent$lambda$9(String str) {
            return AbstractC0147y.d("The device was un-registered from ADM: ", str);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final void handlePush(Context context, Intent intent) {
            Context applicationContext = context.getApplicationContext();
            String action = intent.getAction();
            try {
                handlePush$performWork(action, applicationContext, intent, context);
            } catch (Exception e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new C1277j(14, action, intent), 4, (Object) null);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePush$lambda$3(String str, Intent intent) {
            return "Caught exception while performing the push notification handling work. Action: " + str + " Intent: " + intent;
        }

        /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
        /* JADX WARN: Code restructure failed: missing block: B:11:0x0032, code lost:
        
            if (r8.equals("hms_push_service_routing_action") == false) goto L51;
         */
        /* JADX WARN: Code restructure failed: missing block: B:14:0x003c, code lost:
        
            if (r8.equals("com.amazon.device.messaging.intent.RECEIVE") == false) goto L51;
         */
        /* JADX WARN: Code restructure failed: missing block: B:27:0x005f, code lost:
        
            if (r8.equals("com.braze.action.STORY_TRAVERSE") == false) goto L51;
         */
        /* JADX WARN: Code restructure failed: missing block: B:40:0x0087, code lost:
        
            if (r8.equals("firebase_messaging_service_routing_action") == false) goto L51;
         */
        /* JADX WARN: Code restructure failed: missing block: B:42:0x008a, code lost:
        
            r1.handlePushNotificationPayload(r9, r10);
         */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        private static final void handlePush$performWork(java.lang.String r8, android.content.Context r9, android.content.Intent r10, android.content.Context r11) {
            /*
                com.braze.support.BrazeLogger r0 = com.braze.support.BrazeLogger.INSTANCE
                com.braze.push.BrazePushReceiver$Companion r1 = com.braze.push.BrazePushReceiver.Companion
                com.braze.support.BrazeLogger$Priority r2 = com.braze.support.BrazeLogger.Priority.I
                com.braze.push.h r5 = new com.braze.push.h
                r3 = 3
                r5.<init>(r3, r10)
                r3 = 0
                r4 = 0
                r6 = 6
                r7 = 0
                com.braze.support.BrazeLogger.brazelog$default(r0, r1, r2, r3, r4, r5, r6, r7)
                if (r8 == 0) goto Lb8
                int r2 = r8.length()
                if (r2 != 0) goto L1d
                goto Lb8
            L1d:
                kotlin.jvm.internal.Intrinsics.d(r9)
                com.braze.BrazeInternal.applyPendingRuntimeConfiguration(r9)
                int r2 = r8.hashCode()
                switch(r2) {
                    case -2147185193: goto L9b;
                    case -1799205286: goto L8e;
                    case -1584985748: goto L81;
                    case -1249868226: goto L74;
                    case -743092218: goto L62;
                    case -711830027: goto L59;
                    case -559929808: goto L4c;
                    case 34673601: goto L3f;
                    case 1060266838: goto L36;
                    case 1740454061: goto L2c;
                    default: goto L2a;
                }
            L2a:
                goto La3
            L2c:
                java.lang.String r11 = "hms_push_service_routing_action"
                boolean r8 = r8.equals(r11)
                if (r8 != 0) goto L8a
                goto La3
            L36:
                java.lang.String r11 = "com.amazon.device.messaging.intent.RECEIVE"
                boolean r8 = r8.equals(r11)
                if (r8 != 0) goto L8a
                goto La3
            L3f:
                java.lang.String r9 = "com.braze.action.BRAZE_STORY_CLICKED"
                boolean r8 = r8.equals(r9)
                if (r8 != 0) goto L48
                goto La3
            L48:
                com.braze.push.BrazeNotificationUtils.handlePushStoryPageClicked(r11, r10)
                return
            L4c:
                java.lang.String r11 = "com.braze.action.BRAZE_PUSH_DELETED"
                boolean r8 = r8.equals(r11)
                if (r8 != 0) goto L55
                goto La3
            L55:
                com.braze.push.BrazeNotificationUtils.handleNotificationDeleted(r9, r10)
                return
            L59:
                java.lang.String r11 = "com.braze.action.STORY_TRAVERSE"
                boolean r8 = r8.equals(r11)
                if (r8 != 0) goto L8a
                goto La3
            L62:
                java.lang.String r11 = "com.amazon.device.messaging.intent.REGISTRATION"
                boolean r8 = r8.equals(r11)
                if (r8 != 0) goto L6b
                goto La3
            L6b:
                com.braze.configuration.BrazeConfigurationProvider r8 = new com.braze.configuration.BrazeConfigurationProvider
                r8.<init>(r9)
                r1.handleAdmRegistrationEventIfEnabled(r8, r9, r10)
                return
            L74:
                java.lang.String r9 = "com.braze.action.BRAZE_PUSH_CLICKED"
                boolean r8 = r8.equals(r9)
                if (r8 != 0) goto L7d
                goto La3
            L7d:
                com.braze.push.BrazeNotificationUtils.handleNotificationOpened(r11, r10)
                return
            L81:
                java.lang.String r11 = "firebase_messaging_service_routing_action"
                boolean r8 = r8.equals(r11)
                if (r8 != 0) goto L8a
                goto La3
            L8a:
                r1.handlePushNotificationPayload(r9, r10)
                return
            L8e:
                java.lang.String r9 = "com.braze.action.BRAZE_ACTION_CLICKED"
                boolean r8 = r8.equals(r9)
                if (r8 != 0) goto L97
                goto La3
            L97:
                com.braze.push.BrazeNotificationActionUtils.handleNotificationActionClicked(r11, r10)
                return
            L9b:
                java.lang.String r11 = "com.braze.action.CANCEL_NOTIFICATION"
                boolean r8 = r8.equals(r11)
                if (r8 != 0) goto Lb4
            La3:
                com.braze.support.BrazeLogger$Priority r2 = com.braze.support.BrazeLogger.Priority.W
                com.braze.push.i r5 = new com.braze.push.i
                r8 = 28
                r5.<init>(r8)
                r3 = 0
                r4 = 0
                r6 = 6
                r7 = 0
                com.braze.support.BrazeLogger.brazelog$default(r0, r1, r2, r3, r4, r5, r6, r7)
                return
            Lb4:
                com.braze.push.BrazeNotificationUtils.handleCancelNotificationAction(r9, r10)
                return
            Lb8:
                com.braze.support.BrazeLogger$Priority r2 = com.braze.support.BrazeLogger.Priority.W
                com.braze.push.h r5 = new com.braze.push.h
                r8 = 4
                r5.<init>(r8, r10)
                r3 = 0
                r4 = 0
                r6 = 6
                r7 = 0
                com.braze.support.BrazeLogger.brazelog$default(r0, r1, r2, r3, r4, r5, r6, r7)
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: com.braze.push.BrazePushReceiver.Companion.handlePush$performWork(java.lang.String, android.content.Context, android.content.Intent, android.content.Context):void");
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePush$performWork$lambda$0(Intent intent) {
            return "Received broadcast message. Message: " + intent;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePush$performWork$lambda$1(Intent intent) {
            return "Push action is null. Not handling intent: " + intent;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePush$performWork$lambda$2() {
            return "Received a message not sent from Braze. Ignoring the message.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePushNotificationPayload$lambda$11() {
            return "Not handling non-Braze push message.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePushNotificationPayload$lambda$12(int i) {
            return AbstractC0147y.c(i, "Firebase messaging 'total_deleted' reports ", " messages.");
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePushNotificationPayload$lambda$13(Bundle bundle) {
            return "Push message payload received: " + bundle;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePushNotificationPayload$lambda$14() {
            return "Push message is uninstall tracking push. Doing nothing. Not forwarding this notification to broadcast receivers.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePushNotificationPayload$lambda$16$lambda$15(String str) {
            return android.support.v4.media.session.a.B("Push with identifier '", str, "' has already been seen. Not displaying or forwarding push.");
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePushNotificationPayload$lambda$17() {
            return "Bypassing push display due to test in-app message presence and eager test in-app message display configuration setting.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePushNotificationPayload$lambda$18() {
            return "Received visible push notification";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePushNotificationPayload$lambda$19() {
            return "Push stories not supported on Amazon devices.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePushNotificationPayload$lambda$20() {
            return "Received the initial Push Story notification.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePushNotificationPayload$lambda$21(BrazeNotificationPayload brazeNotificationPayload) {
            return "Creating notification with payload:\n" + brazeNotificationPayload;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePushNotificationPayload$lambda$22() {
            return "Notification created by notification factory was null. Not displaying notification.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePushNotificationPayload$lambda$23(NotificationManagerCompat notificationManagerCompat) {
            return "Value of notificationManager.areNotificationsEnabled() = " + notificationManagerCompat.areNotificationsEnabled();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePushNotificationPayload$lambda$24() {
            return "POST_NOTIFICATIONS permission has not been granted. Not posting notification.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handlePushNotificationPayload$lambda$26() {
            return "Received silent push notification";
        }

        public static /* synthetic */ void handleReceivedIntent$default(Companion companion, Context context, Intent intent, boolean z, int i, Object obj) {
            if ((i & 4) != 0) {
                z = true;
            }
            companion.handleReceivedIntent(context, intent, z);
        }

        @NotNull
        public final BrazeNotificationPayload createPayload(@NotNull Context context, @NotNull BrazeConfigurationProvider appConfigurationProvider, @NotNull Bundle notificationExtras, @NotNull Bundle brazeExtras) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(appConfigurationProvider, "appConfigurationProvider");
            Intrinsics.checkNotNullParameter(notificationExtras, "notificationExtras");
            Intrinsics.checkNotNullParameter(brazeExtras, "brazeExtras");
            return Constants.isAmazonDevice() ? new BrazeNotificationPayload(notificationExtras, BrazeNotificationPayload.Companion.getAttachedBrazeExtras(notificationExtras), context, appConfigurationProvider) : new BrazeNotificationPayload(notificationExtras, brazeExtras, context, appConfigurationProvider);
        }

        public final boolean handleAdmRegistrationEventIfEnabled(@NotNull BrazeConfigurationProvider appConfigurationProvider, @NotNull Context context, @NotNull Intent intent) {
            Intrinsics.checkNotNullParameter(appConfigurationProvider, "appConfigurationProvider");
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(intent, "intent");
            BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new h(2, intent), 6, (Object) null);
            if (!Constants.isAmazonDevice() || !appConfigurationProvider.isAdmMessagingRegistrationEnabled()) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new i(26), 6, (Object) null);
                return false;
            }
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new i(25), 7, (Object) null);
            handleAdmRegistrationIntent(context, intent);
            return true;
        }

        public final boolean handleAdmRegistrationIntent(@NotNull Context context, @NotNull Intent intent) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(intent, "intent");
            String stringExtra = intent.getStringExtra("error");
            String stringExtra2 = intent.getStringExtra("error_description");
            String stringExtra3 = intent.getStringExtra("registration_id");
            String stringExtra4 = intent.getStringExtra("unregistered");
            if (stringExtra != null) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new C1481g(21, stringExtra, stringExtra2), 6, (Object) null);
                return true;
            }
            if (stringExtra3 != null) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new a(stringExtra3, 16), 6, (Object) null);
                Braze.Companion.getInstance(context).setRegisteredPushToken(stringExtra3);
                return true;
            }
            if (stringExtra4 != null) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new a(stringExtra4, 17), 6, (Object) null);
                return true;
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new i(27), 6, (Object) null);
            return false;
        }

        public final boolean handlePushNotificationPayload(@NotNull Context context, @NotNull Intent intent) {
            Companion companion;
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(intent, "intent");
            if (!BrazeNotificationUtils.isBrazePushMessage(intent)) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new i(29), 7, (Object) null);
                return false;
            }
            if ("deleted_messages".equals(intent.getStringExtra("message_type"))) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new com.braze.enums.i(intent.getIntExtra("total_deleted", -1), 9), 6, (Object) null);
                return false;
            }
            Bundle extras = intent.getExtras();
            if (extras == null) {
                return false;
            }
            BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
            BrazeLogger.Priority priority = BrazeLogger.Priority.I;
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new b(extras, 1), 6, (Object) null);
            Bundle attachedBrazeExtras = BrazeNotificationPayload.Companion.getAttachedBrazeExtras(extras);
            extras.putBundle("extra", attachedBrazeExtras);
            if (!extras.containsKey("braze_push_received_timestamp")) {
                extras.putLong("braze_push_received_timestamp", DateTimeUtils.nowInMilliseconds());
            }
            BrazeInternal brazeInternal = BrazeInternal.INSTANCE;
            BrazeConfigurationProvider configurationProvider = brazeInternal.getConfigurationProvider(context);
            BrazeNotificationPayload brazeNotificationPayloadCreatePayload = createPayload(context, configurationProvider, extras, attachedBrazeExtras);
            if (brazeNotificationPayloadCreatePayload.isUninstallTrackingPush()) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new i(20), 6, (Object) null);
                return false;
            }
            String pushUniqueId = brazeNotificationPayloadCreatePayload.getPushUniqueId();
            if (pushUniqueId != null && !brazeInternal.validateAndStorePushId(context, pushUniqueId)) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) BrazePushReceiver.Companion, priority, (Throwable) null, false, (Function0) new a(pushUniqueId, 15), 6, (Object) null);
                return false;
            }
            BrazeNotificationUtils.handleContentCardsSerializedCardIfPresent(brazeNotificationPayloadCreatePayload);
            BrazeNotificationUtils.requestGeofenceRefreshIfAppropriate(brazeNotificationPayloadCreatePayload);
            BrazeNotificationUtils.refreshFeatureFlagsIfAppropriate(brazeNotificationPayloadCreatePayload);
            BrazeNotificationUtils.refreshBannersIfAppropriate(brazeNotificationPayloadCreatePayload);
            if (brazeNotificationPayloadCreatePayload.getShouldFetchTestTriggers() && configurationProvider.isInAppMessageTestPushEagerDisplayEnabled() && BrazeInAppMessageManager.Companion.getInstance().getActivity() != null) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new i(21), 7, (Object) null);
                BrazeInternal.handleInAppMessageTestPush(context, intent);
                return false;
            }
            if (!BrazeNotificationUtils.isNotificationMessage(intent)) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new j(2), 7, (Object) null);
                BrazeNotificationUtils.sendPushMessageReceivedBroadcast(context, extras, brazeNotificationPayloadCreatePayload);
                return false;
            }
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new i(22), 7, (Object) null);
            int notificationId = BrazeNotificationUtils.getNotificationId(brazeNotificationPayloadCreatePayload);
            extras.putInt("nid", notificationId);
            if (brazeNotificationPayloadCreatePayload.isPushStory()) {
                if (Constants.isAmazonDevice()) {
                    BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new i(23), 7, (Object) null);
                    return false;
                }
                if (!extras.containsKey("braze_story_newly_received")) {
                    BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new i(24), 7, (Object) null);
                    extras.putBoolean("braze_story_newly_received", true);
                }
            }
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new c(brazeNotificationPayloadCreatePayload, 2), 6, (Object) null);
            Notification notificationCreateNotification = BrazeNotificationUtils.getActiveNotificationFactory().createNotification(brazeNotificationPayloadCreatePayload);
            if (notificationCreateNotification == null) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new j(0), 7, (Object) null);
                return false;
            }
            NotificationManagerCompat notificationManagerCompatFrom = NotificationManagerCompat.from(context);
            Intrinsics.checkNotNullExpressionValue(notificationManagerCompatFrom, "from(...)");
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new f(notificationManagerCompatFrom, 6), 7, (Object) null);
            if (androidx.core.content.c.a(context, "android.permission.POST_NOTIFICATIONS") == 0) {
                notificationManagerCompatFrom.notify("appboy_notification", notificationId, notificationCreateNotification);
                companion = this;
            } else {
                companion = this;
                BrazeLogger.brazelog$default(brazeLogger, (Object) companion, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new j(1), 7, (Object) null);
            }
            BrazeNotificationUtils.sendPushMessageReceivedBroadcast(context, extras, brazeNotificationPayloadCreatePayload);
            BrazeNotificationUtils.wakeScreenIfAppropriate(context, configurationProvider, extras);
            Integer pushDuration = brazeNotificationPayloadCreatePayload.getPushDuration();
            if (pushDuration != null) {
                BrazeNotificationUtils.setNotificationDurationAlarm(context, BrazePushReceiver.class, notificationId, pushDuration.intValue());
            }
            companion.logNotificationMetadata$android_sdk_ui_release(context, brazeNotificationPayloadCreatePayload);
            return true;
        }

        public final void handleReceivedIntent(@NotNull Context context, @NotNull Intent intent, boolean z) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(intent, "intent");
            if (z) {
                E.A(BrazeCoroutineScope.INSTANCE, null, null, new BrazePushReceiver$Companion$handleReceivedIntent$1(context, intent, null), 3);
            } else {
                handlePush(context, intent);
            }
        }

        public final void logNotificationMetadata$android_sdk_ui_release(@NotNull Context context, @NotNull BrazeNotificationPayload payload) {
            String campaignId;
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(payload, "payload");
            if (payload.isPushDeliveryEnabled() && (campaignId = payload.getCampaignId()) != null) {
                long flushMinMinutes = payload.getFlushMinMinutes();
                if (flushMinMinutes < 0) {
                    flushMinMinutes = 0;
                }
                long flushMaxMinutes = payload.getFlushMaxMinutes();
                if (flushMaxMinutes < flushMinMinutes) {
                    flushMaxMinutes = flushMinMinutes;
                }
                TimeUnit timeUnit = TimeUnit.MINUTES;
                long millis = timeUnit.toMillis(flushMinMinutes);
                if (flushMaxMinutes > flushMinMinutes) {
                    kotlin.random.d dVar = kotlin.random.e.a;
                    long millis2 = timeUnit.toMillis(flushMaxMinutes);
                    dVar.getClass();
                    millis = kotlin.random.e.b.g(millis, millis2);
                }
                BrazeInternal.INSTANCE.logPushDelivery(context, campaignId, millis);
            }
            String campaignId2 = payload.getCampaignId();
            if (campaignId2 != null) {
                BrazeInternal.INSTANCE.logPushCampaign(context, campaignId2);
            }
        }

        private Companion() {
        }
    }

    @Override // android.content.BroadcastReceiver
    public void onReceive(@NotNull Context context, @NotNull Intent intent) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(intent, "intent");
        Companion.handleReceivedIntent$default(Companion, context, intent, false, 4, null);
    }
}
