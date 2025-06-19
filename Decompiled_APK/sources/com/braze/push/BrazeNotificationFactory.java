package com.braze.push;

import android.app.Notification;
import android.content.Context;
import android.os.Bundle;
import androidx.core.app.C1034v;
import com.braze.IBrazeNotificationFactory;
import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.models.push.BrazeNotificationPayload;
import com.braze.support.BrazeLogger;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class BrazeNotificationFactory implements IBrazeNotificationFactory {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @NotNull
    private static final BrazeNotificationFactory internalInstance = new BrazeNotificationFactory();

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String populateNotificationBuilder$lambda$0(BrazeNotificationPayload brazeNotificationPayload) {
            return "Using BrazeNotificationPayload: " + brazeNotificationPayload;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String populateNotificationBuilder$lambda$1() {
            return "BrazeNotificationPayload has null context. Not creating notification";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String populateNotificationBuilder$lambda$2() {
            return "BrazeNotificationPayload has null app configuration provider. Not creating notification";
        }

        @NotNull
        public final BrazeNotificationFactory getInstance() {
            return BrazeNotificationFactory.internalInstance;
        }

        public final C1034v populateNotificationBuilder(@NotNull BrazeNotificationPayload payload) {
            Intrinsics.checkNotNullParameter(payload, "payload");
            BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new c(payload, 0), 6, (Object) null);
            Context context = payload.getContext();
            if (context == null) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new k(12), 7, (Object) null);
                return null;
            }
            BrazeConfigurationProvider configurationProvider = payload.getConfigurationProvider();
            if (configurationProvider == null) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new k(13), 7, (Object) null);
                return null;
            }
            Bundle notificationExtras = payload.getNotificationExtras();
            BrazeNotificationUtils.prefetchBitmapsIfNewlyReceivedStoryPush(payload);
            C1034v c1034v = new C1034v(context, BrazeNotificationUtils.getOrCreateNotificationChannelId(payload));
            c1034v.c(16, true);
            Intrinsics.checkNotNullExpressionValue(c1034v, "setAutoCancel(...)");
            BrazeNotificationUtils.setTitleIfPresent(c1034v, payload);
            BrazeNotificationUtils.setContentIfPresent(c1034v, payload);
            BrazeNotificationUtils.setTickerIfPresent(c1034v, payload);
            BrazeNotificationUtils.setSetShowWhen(c1034v, payload);
            BrazeNotificationUtils.setContentIntentIfPresent(context, c1034v, notificationExtras);
            BrazeNotificationUtils.setDeleteIntent(context, c1034v, notificationExtras);
            BrazeNotificationUtils.setSmallIcon(configurationProvider, c1034v);
            BrazeNotificationUtils.setLargeIconIfPresentAndSupported(c1034v, payload);
            BrazeNotificationUtils.setSoundIfPresentAndSupported(c1034v, payload);
            BrazeNotificationUtils.setSummaryTextIfPresentAndSupported(c1034v, payload);
            BrazeNotificationUtils.setPriorityIfPresentAndSupported(c1034v, payload);
            BrazeNotificationStyleFactory.Companion.setStyleIfSupported(c1034v, payload);
            BrazeNotificationActionUtils.addNotificationActions(c1034v, payload);
            BrazeNotificationUtils.setAccentColorIfPresentAndSupported(c1034v, payload);
            BrazeNotificationUtils.setCategoryIfPresentAndSupported(c1034v, payload);
            BrazeNotificationUtils.setVisibilityIfPresentAndSupported(c1034v, payload);
            BrazeNotificationUtils.setPublicVersionIfPresentAndSupported(c1034v, payload);
            BrazeNotificationUtils.setNotificationBadgeNumberIfPresent(c1034v, payload);
            return c1034v;
        }

        private Companion() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String createNotification$lambda$0() {
        return "Notification could not be built. Returning null as created notification";
    }

    @Override // com.braze.IBrazeNotificationFactory
    public Notification createNotification(@NotNull BrazeNotificationPayload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        C1034v c1034vPopulateNotificationBuilder = Companion.populateNotificationBuilder(payload);
        if (c1034vPopulateNotificationBuilder != null) {
            return c1034vPopulateNotificationBuilder.a();
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new k(11), 6, (Object) null);
        return null;
    }
}
