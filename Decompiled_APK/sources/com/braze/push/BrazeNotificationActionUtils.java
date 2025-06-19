package com.braze.push;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import androidx.core.app.C1029p;
import androidx.core.app.C1034v;
import androidx.core.app.T;
import com.braze.Braze;
import com.braze.IBrazeDeeplinkHandler;
import com.braze.models.push.BrazeNotificationPayload;
import com.braze.support.BrazeLogger;
import com.braze.support.IntentUtils;
import com.braze.ui.BrazeDeeplinkHandler;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class BrazeNotificationActionUtils {

    @NotNull
    public static final BrazeNotificationActionUtils INSTANCE = new BrazeNotificationActionUtils();

    private BrazeNotificationActionUtils() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addNotificationAction$lambda$10(Bundle bundle) {
        return "Added action with bundle: " + bundle;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addNotificationAction$lambda$7() {
        return "Cannot add notification action with null context from payload";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addNotificationAction$lambda$8(String str) {
        StringBuilder sbY = android.support.v4.media.session.a.y("Adding notification action with type: ", str, "Setting intent class to notification receiver: ");
        sbY.append(BrazeNotificationUtils.getNotificationReceiverClass());
        return sbY.toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addNotificationAction$lambda$9(String str) {
        return android.support.v4.media.session.a.B("Adding notification action with type: ", str, " Setting intent class to trampoline activity");
    }

    public static final void addNotificationActions(@NotNull C1034v notificationBuilder, @NotNull BrazeNotificationPayload payload) {
        Intrinsics.checkNotNullParameter(notificationBuilder, "notificationBuilder");
        Intrinsics.checkNotNullParameter(payload, "payload");
        if (payload.getContext() == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new k(8), 7, (Object) null);
            return;
        }
        List<BrazeNotificationPayload.ActionButton> actionButtons = payload.getActionButtons();
        if (actionButtons.isEmpty()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new k(9), 7, (Object) null);
            return;
        }
        for (BrazeNotificationPayload.ActionButton actionButton : actionButtons) {
            BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
            BrazeNotificationActionUtils brazeNotificationActionUtils = INSTANCE;
            BrazeLogger.brazelog$default(brazeLogger, (Object) brazeNotificationActionUtils, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new f(actionButton, 3), 6, (Object) null);
            brazeNotificationActionUtils.addNotificationAction(notificationBuilder, payload, actionButton);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addNotificationActions$lambda$0() {
        return "Context cannot be null when adding notification buttons.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addNotificationActions$lambda$1() {
        return "No action buttons present. Not adding notification actions";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addNotificationActions$lambda$2(BrazeNotificationPayload.ActionButton actionButton) {
        return "Adding action button: " + actionButton;
    }

    /* JADX WARN: Removed duplicated region for block: B:41:0x0095 A[Catch: Exception -> 0x00e5, TryCatch #0 {Exception -> 0x00e5, blocks: (B:3:0x000e, B:5:0x0016, B:8:0x001e, B:10:0x002c, B:18:0x0043, B:29:0x0060, B:32:0x006b, B:34:0x0071, B:36:0x0078, B:38:0x0085, B:40:0x008b, B:42:0x0098, B:44:0x00a7, B:46:0x00ab, B:41:0x0095, B:21:0x004c, B:24:0x0055, B:26:0x0059, B:49:0x00bf, B:51:0x00d1), top: B:57:0x000e }] */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00a7 A[Catch: Exception -> 0x00e5, TryCatch #0 {Exception -> 0x00e5, blocks: (B:3:0x000e, B:5:0x0016, B:8:0x001e, B:10:0x002c, B:18:0x0043, B:29:0x0060, B:32:0x006b, B:34:0x0071, B:36:0x0078, B:38:0x0085, B:40:0x008b, B:42:0x0098, B:44:0x00a7, B:46:0x00ab, B:41:0x0095, B:21:0x004c, B:24:0x0055, B:26:0x0059, B:49:0x00bf, B:51:0x00d1), top: B:57:0x000e }] */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00ab A[Catch: Exception -> 0x00e5, TryCatch #0 {Exception -> 0x00e5, blocks: (B:3:0x000e, B:5:0x0016, B:8:0x001e, B:10:0x002c, B:18:0x0043, B:29:0x0060, B:32:0x006b, B:34:0x0071, B:36:0x0078, B:38:0x0085, B:40:0x008b, B:42:0x0098, B:44:0x00a7, B:46:0x00ab, B:41:0x0095, B:21:0x004c, B:24:0x0055, B:26:0x0059, B:49:0x00bf, B:51:0x00d1), top: B:57:0x000e }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void handleNotificationActionClicked(@org.jetbrains.annotations.NotNull android.content.Context r12, @org.jetbrains.annotations.NotNull android.content.Intent r13) {
        /*
            Method dump skipped, instructions count: 251
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.push.BrazeNotificationActionUtils.handleNotificationActionClicked(android.content.Context, android.content.Intent):void");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String handleNotificationActionClicked$lambda$3() {
        return "Notification action button type was blank or null. Doing nothing.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String handleNotificationActionClicked$lambda$4() {
        return "Not handling deep links automatically, skipping deep link handling";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String handleNotificationActionClicked$lambda$5() {
        return "Unknown notification action button clicked. Doing nothing.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String handleNotificationActionClicked$lambda$6() {
        return "Caught exception while handling notification action button click.";
    }

    public final void addNotificationAction(@NotNull C1034v notificationBuilder, @NotNull BrazeNotificationPayload payload, @NotNull BrazeNotificationPayload.ActionButton actionButton) {
        PendingIntent activity;
        Intrinsics.checkNotNullParameter(notificationBuilder, "notificationBuilder");
        Intrinsics.checkNotNullParameter(payload, "payload");
        Intrinsics.checkNotNullParameter(actionButton, "actionButton");
        Context context = payload.getContext();
        if (context == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new k(10), 7, (Object) null);
            return;
        }
        Bundle bundle = new Bundle(payload.getNotificationExtras());
        actionButton.putIntoBundle(bundle);
        String type = actionButton.getType();
        int immutablePendingIntentFlags = 134217728 | IntentUtils.getImmutablePendingIntentFlags();
        if ("ab_none".equals(type)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new a(type, 6), 6, (Object) null);
            Intent intent = new Intent("com.braze.action.BRAZE_ACTION_CLICKED").setClass(context, BrazeNotificationUtils.getNotificationReceiverClass());
            intent.putExtras(bundle);
            activity = PendingIntent.getBroadcast(context, IntentUtils.getRequestCode(), intent, immutablePendingIntentFlags);
        } else {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new a(type, 7), 6, (Object) null);
            Intent intent2 = new Intent("com.braze.action.BRAZE_ACTION_CLICKED").setClass(context, NotificationTrampolineActivity.class);
            intent2.setFlags(intent2.getFlags() | BrazeDeeplinkHandler.Companion.getInstance().getIntentFlags(IBrazeDeeplinkHandler.IntentFlagPurpose.NOTIFICATION_ACTION_WITH_DEEPLINK));
            intent2.putExtras(bundle);
            activity = PendingIntent.getActivity(context, IntentUtils.getRequestCode(), intent2, immutablePendingIntentFlags);
        }
        PendingIntent pendingIntent = activity;
        String text = actionButton.getText();
        Bundle bundle2 = new Bundle();
        CharSequence charSequenceB = C1034v.b(text);
        bundle2.putAll(new Bundle(bundle));
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        notificationBuilder.b.add(new C1029p(null, charSequenceB, pendingIntent, bundle2, arrayList2.isEmpty() ? null : (T[]) arrayList2.toArray(new T[arrayList2.size()]), arrayList.isEmpty() ? null : (T[]) arrayList.toArray(new T[arrayList.size()])));
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new b(bundle, 0), 6, (Object) null);
    }

    public final void logNotificationActionClicked(@NotNull Context context, @NotNull Intent intent, String str) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(intent, "intent");
        Braze.Companion.getInstance(context).logPushNotificationActionClicked(intent.getStringExtra("cid"), intent.getStringExtra("braze_action_id"), str);
    }
}
