package com.braze.configuration;

import android.content.Context;
import android.content.SharedPreferences;
import com.braze.BrazeInternal;
import com.braze.D;
import com.braze.Y;
import com.braze.enums.BrazeSdkMetadata;
import com.braze.support.BrazeLogger;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class RuntimeAppConfigurationProvider {
    public static final f Companion = new f();
    private final Context context;
    private SharedPreferences.Editor editor;
    private final SharedPreferences storageMap;

    public RuntimeAppConfigurationProvider(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.appboy.override.configuration.cache", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        this.storageMap = sharedPreferences;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String clearAllConfigurationValues$lambda$2() {
        return "Clearing Braze Override configuration cache";
    }

    private final void putBoolean(String str, Boolean bool) {
        if (bool != null) {
            boolean zBooleanValue = bool.booleanValue();
            SharedPreferences.Editor editor = this.editor;
            if (editor != null) {
                editor.putBoolean(str, zBooleanValue);
            }
        }
    }

    private final <T extends Enum<T>> void putEnumSet(EnumSet<T> enumSet, String str) {
        if (enumSet == null) {
            return;
        }
        Set<String> setA = com.braze.support.f.a(enumSet);
        SharedPreferences.Editor editor = this.editor;
        if (editor != null) {
            editor.putStringSet(str, setA);
        }
    }

    private final void putInt(String str, Integer num) {
        if (num != null) {
            int iIntValue = num.intValue();
            SharedPreferences.Editor editor = this.editor;
            if (editor != null) {
                editor.putInt(str, iIntValue);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setConfiguration$lambda$0(BrazeConfig brazeConfig) {
        return "Setting Braze Override configuration with config: " + brazeConfig;
    }

    public final void applyEdit() {
        SharedPreferences.Editor editor = this.editor;
        if (editor != null) {
            editor.apply();
        }
    }

    public final void clearAllConfigurationValues() {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new Y(29), 7, (Object) null);
        this.storageMap.edit().clear().apply();
    }

    public final boolean containsKey(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        return this.storageMap.contains(key);
    }

    public final boolean getBooleanValue(String key, boolean z) {
        Intrinsics.checkNotNullParameter(key, "key");
        return this.storageMap.getBoolean(key, z);
    }

    public final int getIntValue(String key, int i) {
        Intrinsics.checkNotNullParameter(key, "key");
        return this.storageMap.getInt(key, i);
    }

    public final Set<String> getStringSetValue(String key, Set<String> set) {
        Intrinsics.checkNotNullParameter(key, "key");
        return this.storageMap.getStringSet(key, set);
    }

    public final String getStringValue(String key, String str) {
        Intrinsics.checkNotNullParameter(key, "key");
        return this.storageMap.getString(key, str);
    }

    public final void putEnumAsString(String key, Enum<?> r3) {
        Intrinsics.checkNotNullParameter(key, "key");
        if (r3 != null) {
            putString(key, r3.toString());
        }
    }

    public final void putString(String key, String str) {
        SharedPreferences.Editor editor;
        Intrinsics.checkNotNullParameter(key, "key");
        if (str == null || (editor = this.editor) == null) {
            return;
        }
        editor.putString(key, str);
    }

    public final void setConfiguration(BrazeConfig config) {
        Intrinsics.checkNotNullParameter(config, "config");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new D(config, 1), 6, (Object) null);
        startEdit();
        b bVar = b.b;
        putString("com_braze_api_key", config.apiKey);
        putString("com_braze_server_target", config.serverTarget);
        putEnumAsString("com_braze_sdk_flavor", config.sdkFlavor);
        putBoolean("com_braze_newsfeed_unread_visual_indicator_on", config.isNewsFeedVisualIndicatorOn);
        putString("com_braze_custom_endpoint", config.customEndpoint);
        putString("com_braze_push_small_notification_icon", config.smallNotificationIcon);
        putString("com_braze_push_large_notification_icon", config.largeNotificationIcon);
        putInt("com_braze_session_timeout", config.sessionTimeout);
        putInt("com_braze_default_notification_accent_color", config.defaultNotificationAccentColor);
        putInt("com_braze_trigger_action_minimum_time_interval_seconds", config.triggerActionMinimumTimeIntervalSeconds);
        putBoolean("com_braze_push_adm_messaging_registration_enabled", config.isAdmMessagingRegistrationEnabled);
        putBoolean("com_braze_handle_push_deep_links_automatically", config.willHandlePushDeepLinksAutomatically);
        putBoolean("com_braze_enable_location_collection", config.isLocationCollectionEnabled);
        putInt("com_braze_data_flush_interval_bad_network", config.badNetworkInterval);
        putInt("com_braze_data_flush_interval_good_network", config.goodNetworkInterval);
        putInt("com_braze_data_flush_interval_great_network", config.greatNetworkInterval);
        putString("com_braze_default_notification_channel_name", config.defaultNotificationChannelName);
        putString("com_braze_default_notification_channel_description", config.defaultNotificationChannelDescription);
        putBoolean("com_braze_push_deep_link_back_stack_activity_enabled", config.isPushDeepLinkBackStackActivityEnabled);
        putString("com_braze_push_deep_link_back_stack_activity_class_name", config.pushDeepLinkBackStackActivityClassName);
        putBoolean("com_braze_session_start_based_timeout_enabled", config.isSessionStartBasedTimeoutEnabled);
        putBoolean("com_braze_firebase_cloud_messaging_registration_enabled", config.isFirebaseCloudMessagingRegistrationEnabled);
        putString("com_braze_firebase_cloud_messaging_sender_id", config.firebaseCloudMessagingSenderIdKey);
        putBoolean("com_braze_content_cards_unread_visual_indicator_enabled", config.isContentCardsUnreadVisualIndicatorEnabled);
        putBoolean("com_braze_device_object_whitelisting_enabled", config.isDeviceObjectAllowlistEnabled);
        putBoolean("com_braze_device_in_app_message_accessibility_exclusive_mode_enabled", config.isInAppMessageAccessibilityExclusiveModeEnabled);
        putBoolean("com_braze_push_wake_screen_for_notification_enabled", config.isPushWakeScreenForNotificationEnabled);
        putBoolean("com_braze_push_notification_html_rendering_enabled", config.isPushHtmlRenderingEnabled);
        putBoolean("com_braze_does_push_story_dismiss_on_click", config.doesPushStoryDismissOnClick);
        putBoolean("com_braze_geofences_enabled", config.areGeofencesEnabled);
        putBoolean("com_braze_in_app_message_push_test_eager_display_enabled", config.isInAppMessageTestPushEagerDisplayEnabled);
        putString("com_braze_custom_html_webview_activity_class_name", config.customHtmlWebViewActivityClassName);
        putBoolean("com_braze_automatic_geofence_requests_enabled", config.areAutomaticGeofenceRequestsEnabled);
        putInt("com_braze_in_app_message_webview_client_max_onpagefinished_wait_ms", config.inAppMessageWebViewClientMaxOnPageFinishedWaitMs);
        putBoolean("com_braze_firebase_messaging_service_automatically_register_on_new_token", config.isFirebaseMessagingServiceOnNewTokenRegistrationEnabled);
        putBoolean("com_braze_sdk_authentication_enabled", config.isSdkAuthEnabled);
        putBoolean("com_braze_require_touch_mode_for_html_in_app_messages", config.isTouchModeRequiredForHtmlInAppMessages);
        putBoolean("com_braze_html_in_app_message_apply_insets", config.isHtmlInAppMessageApplyWindowInsetsEnabled);
        putBoolean("com_braze_html_in_app_message_enable_html_link_target", config.isHtmlInAppMessageHtmlLinkTargetEnabled);
        putEnumSet(config.deviceObjectAllowlist, "com_braze_device_object_whitelist");
        putEnumSet(config.customLocationProviderNames, "com_braze_custom_location_providers_list");
        EnumSet<BrazeSdkMetadata> enumSet = config.brazeSdkMetadata;
        if (enumSet != null) {
            updateEnumSetData("com_braze_sdk_metadata", enumSet);
        }
        putBoolean("com_braze_fallback_firebase_cloud_messaging_service_enabled", config.isFallbackFirebaseMessagingServiceEnabled);
        putString("com_braze_fallback_firebase_cloud_messaging_service_classpath", config.fallbackFirebaseMessagingServiceClasspath);
        putBoolean("com_braze_optin_when_push_authorized", config.shouldOptInWhenPushAuthorized);
        putBoolean("com_braze_use_activity_window_flag_secure", config.shouldUseWindowFlagSecureInActivities);
        putBoolean("com_braze_persist_webview_when_backgrounding_app", config.shouldPersistWebViewWhenBackgroundingApp);
        putBoolean("com_braze_in_app_message_add_status_bar_padding", config.shouldAddStatusBarPaddingToInAppMessages);
        applyEdit();
        BrazeInternal.INSTANCE.getConfigurationProvider(this.context).resetCache$android_sdk_base_release();
    }

    public final void startEdit() {
        this.editor = this.storageMap.edit();
    }

    public final <T extends Enum<T>> void updateEnumSetData(String key, EnumSet<T> updateValue) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(updateValue, "updateValue");
        Set<String> stringSetValue = getStringSetValue(key, new HashSet());
        if (stringSetValue != null) {
            stringSetValue.addAll(com.braze.support.f.a(updateValue));
        }
        this.storageMap.edit().putStringSet(key, stringSetValue).apply();
    }
}
