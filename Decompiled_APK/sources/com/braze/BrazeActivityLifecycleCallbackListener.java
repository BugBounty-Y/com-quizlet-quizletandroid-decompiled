package com.braze;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.os.Bundle;
import com.braze.Braze;
import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.push.NotificationTrampolineActivity;
import com.braze.support.BrazeLogger;
import com.braze.ui.inappmessage.BrazeInAppMessageManager;
import java.lang.ref.WeakReference;
import java.util.Set;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class BrazeActivityLifecycleCallbackListener implements Application.ActivityLifecycleCallbacks {

    @NotNull
    public static final Companion Companion = new Companion(null);
    private static WeakReference<Activity> currentActivityRef;

    @NotNull
    private Set<? extends Class<?>> inAppMessagingRegistrationBlocklist;
    private final boolean registerInAppMessageManager;

    @NotNull
    private Set<? extends Class<?>> sessionHandlingBlocklist;
    private final boolean sessionHandlingEnabled;
    private Boolean shouldPersistWebView;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String _get_activity_$lambda$0() {
            return "BrazeActivityLifecycleCallbackListener.currentActivity is null. Ensure that BrazeActivityLifecycleCallbackListener is registered in your Application class.";
        }

        public final Activity getActivity() {
            WeakReference weakReference = BrazeActivityLifecycleCallbackListener.currentActivityRef;
            Activity activity = weakReference != null ? (Activity) weakReference.get() : null;
            if (activity == null) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new M(15), 6, (Object) null);
            }
            return activity;
        }

        private Companion() {
        }
    }

    public BrazeActivityLifecycleCallbackListener(boolean z, boolean z2, Set<? extends Class<?>> set, Set<? extends Class<?>> set2) {
        this.sessionHandlingEnabled = z;
        this.registerInAppMessageManager = z2;
        this.inAppMessagingRegistrationBlocklist = set == null ? kotlin.collections.M.a : set;
        this.sessionHandlingBlocklist = set2 == null ? kotlin.collections.M.a : set2;
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.Priority priority = BrazeLogger.Priority.V;
        final int i = 0;
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, new Function0(this) { // from class: com.braze.O
            public final /* synthetic */ BrazeActivityLifecycleCallbackListener b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i) {
                    case 0:
                        return BrazeActivityLifecycleCallbackListener._init_$lambda$0(this.b);
                    default:
                        return BrazeActivityLifecycleCallbackListener._init_$lambda$1(this.b);
                }
            }
        }, 6, (Object) null);
        final int i2 = 1;
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, new Function0(this) { // from class: com.braze.O
            public final /* synthetic */ BrazeActivityLifecycleCallbackListener b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i2) {
                    case 0:
                        return BrazeActivityLifecycleCallbackListener._init_$lambda$0(this.b);
                    default:
                        return BrazeActivityLifecycleCallbackListener._init_$lambda$1(this.b);
                }
            }
        }, 6, (Object) null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String _init_$lambda$0(BrazeActivityLifecycleCallbackListener brazeActivityLifecycleCallbackListener) {
        return "BrazeActivityLifecycleCallbackListener using in-app messaging blocklist: " + brazeActivityLifecycleCallbackListener.inAppMessagingRegistrationBlocklist;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String _init_$lambda$1(BrazeActivityLifecycleCallbackListener brazeActivityLifecycleCallbackListener) {
        return "BrazeActivityLifecycleCallbackListener using session handling blocklist: " + brazeActivityLifecycleCallbackListener.sessionHandlingBlocklist;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onActivityCreated$lambda$10(Activity activity) {
        return "Automatically calling lifecycle method: ensureSubscribedToInAppMessageEvents for class: " + activity.getClass();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onActivityPaused$lambda$8(Activity activity) {
        return "Automatically calling lifecycle method: unregisterInAppMessageManager for class: " + activity.getClass();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onActivityPaused$lambda$9() {
        return "Skipping unregisterInAppMessageManager in onActivityPaused because shouldPersistWebView is true";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onActivityResumed$lambda$6() {
        return "Activity is different from previous activity. Unregistering in-app message manager";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onActivityResumed$lambda$7(Activity activity) {
        return "Automatically calling lifecycle method: registerInAppMessageManager for class: " + activity.getClass();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onActivityStarted$lambda$4(Activity activity) {
        return "Automatically calling lifecycle method: openSession for class: " + activity.getClass();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onActivityStopped$lambda$5(Activity activity) {
        return "Automatically calling lifecycle method: closeSession for class: " + activity.getClass();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String shouldHandleLifecycleMethodsInActivity$lambda$11() {
        return "Skipping automatic registration for notification trampoline activity class.";
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityCreated(@NotNull Activity activity, Bundle bundle) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new N(3, activity), 6, (Object) null);
        BrazeInAppMessageManager companion = BrazeInAppMessageManager.Companion.getInstance();
        Context applicationContext = activity.getApplicationContext();
        Intrinsics.checkNotNullExpressionValue(applicationContext, "getApplicationContext(...)");
        companion.ensureSubscribedToInAppMessageEvents(applicationContext);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityDestroyed(@NotNull Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPaused(@NotNull Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        if (this.registerInAppMessageManager && shouldHandleLifecycleMethodsInActivity(activity, false)) {
            if (this.shouldPersistWebView == null) {
                Context applicationContext = activity.getApplicationContext();
                Intrinsics.checkNotNullExpressionValue(applicationContext, "getApplicationContext(...)");
                this.shouldPersistWebView = Boolean.valueOf(new BrazeConfigurationProvider(applicationContext).getShouldPersistWebViewWhenBackgroundingApp());
            }
            if (Intrinsics.b(this.shouldPersistWebView, Boolean.TRUE)) {
                BrazeInAppMessageManager.Companion.getInstance().pauseWebviewIfNecessary$android_sdk_ui_release();
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new M(12), 6, (Object) null);
            } else {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new N(1, activity), 6, (Object) null);
                BrazeInAppMessageManager.Companion.getInstance().unregisterInAppMessageManager(activity);
            }
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityResumed(@NotNull Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        if (this.registerInAppMessageManager) {
            if (shouldHandleLifecycleMethodsInActivity(activity, false)) {
                WeakReference<Activity> weakReference = currentActivityRef;
                Activity activity2 = weakReference != null ? weakReference.get() : null;
                Boolean bool = this.shouldPersistWebView;
                Boolean bool2 = Boolean.TRUE;
                if (Intrinsics.b(bool, bool2) && activity2 != null && !activity2.equals(activity)) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new M(13), 6, (Object) null);
                    BrazeInAppMessageManager.Companion.getInstance().unregisterInAppMessageManager(activity);
                }
                if (Intrinsics.b(this.shouldPersistWebView, bool2) && activity2 != null && activity2.equals(activity)) {
                    BrazeInAppMessageManager.Companion.getInstance().resumeWebviewIfNecessary$android_sdk_ui_release();
                } else {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new N(4, activity), 6, (Object) null);
                    BrazeInAppMessageManager.Companion.getInstance().registerInAppMessageManager(activity);
                }
            } else {
                BrazeInAppMessageManager.Companion.getInstance().unregisterInAppMessageManager(activity);
            }
        }
        currentActivityRef = new WeakReference<>(activity);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivitySaveInstanceState(@NotNull Activity activity, @NotNull Bundle bundle) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        Intrinsics.checkNotNullParameter(bundle, "bundle");
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityStarted(@NotNull Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        if (this.sessionHandlingEnabled && shouldHandleLifecycleMethodsInActivity(activity, true)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new N(2, activity), 6, (Object) null);
            Braze.Companion companion = Braze.Companion;
            Context applicationContext = activity.getApplicationContext();
            Intrinsics.checkNotNullExpressionValue(applicationContext, "getApplicationContext(...)");
            companion.getInstance(applicationContext).openSession(activity);
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityStopped(@NotNull Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        if (this.sessionHandlingEnabled && shouldHandleLifecycleMethodsInActivity(activity, true)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new N(0, activity), 6, (Object) null);
            Braze.Companion companion = Braze.Companion;
            Context applicationContext = activity.getApplicationContext();
            Intrinsics.checkNotNullExpressionValue(applicationContext, "getApplicationContext(...)");
            companion.getInstance(applicationContext).closeSession(activity);
        }
    }

    public final boolean shouldHandleLifecycleMethodsInActivity(@NotNull Activity activity, boolean z) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        Class<?> cls = activity.getClass();
        if (!cls.equals(NotificationTrampolineActivity.class)) {
            return z ? !this.sessionHandlingBlocklist.contains(cls) : !this.inAppMessagingRegistrationBlocklist.contains(cls);
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new M(14), 6, (Object) null);
        return false;
    }

    public BrazeActivityLifecycleCallbackListener(boolean z, boolean z2, Set set, Set set2, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? true : z, (i & 2) != 0 ? true : z2, (i & 4) != 0 ? kotlin.collections.M.a : set, (i & 8) != 0 ? kotlin.collections.M.a : set2);
    }
}
