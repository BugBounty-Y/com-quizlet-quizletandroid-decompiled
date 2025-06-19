package com.braze.configuration;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class b {
    public static final b b;
    public static final b c;
    public static final /* synthetic */ b[] d;
    public final String a;

    static {
        b bVar = new b("EPHEMERAL_EVENTS_ENABLED", 0, "com_braze_ephemeral_events_enabled");
        b bVar2 = new b("EPHEMERAL_EVENTS_KEYS", 1, "com_braze_ephemeral_events_keys");
        b bVar3 = new b("API_KEY", 2, "com_braze_api_key");
        b bVar4 = new b("SERVER_TARGET_KEY", 3, "com_braze_server_target");
        b bVar5 = new b("ADM_MESSAGING_REGISTRATION_ENABLED_KEY", 4, "com_braze_push_adm_messaging_registration_enabled");
        b bVar6 = new b("SMALL_NOTIFICATION_ICON_KEY", 5, "com_braze_push_small_notification_icon");
        b bVar7 = new b("LARGE_NOTIFICATION_ICON_KEY", 6, "com_braze_push_large_notification_icon");
        b bVar8 = new b("SESSION_TIMEOUT_KEY", 7, "com_braze_session_timeout");
        b bVar9 = new b("ENABLE_LOCATION_COLLECTION_KEY", 8, "com_braze_enable_location_collection");
        b bVar10 = new b("DEFAULT_NOTIFICATION_ACCENT_COLOR_KEY", 9, "com_braze_default_notification_accent_color");
        b bVar11 = new b("TRIGGER_ACTION_MINIMUM_TIME_INTERVAL_KEY_SECONDS", 10, "com_braze_trigger_action_minimum_time_interval_seconds");
        b bVar12 = new b("HANDLE_PUSH_DEEP_LINKS_AUTOMATICALLY", 11, "com_braze_handle_push_deep_links_automatically");
        b bVar13 = new b("NEWSFEED_UNREAD_VISUAL_INDICATOR_ON", 12, "com_braze_newsfeed_unread_visual_indicator_on");
        b bVar14 = new b("SDK_FLAVOR", 13, "com_braze_sdk_flavor");
        b bVar15 = new b("CUSTOM_ENDPOINT", 14, "com_braze_custom_endpoint");
        b bVar16 = new b("DEFAULT_NOTIFICATION_CHANNEL_NAME", 15, "com_braze_default_notification_channel_name");
        b bVar17 = new b("DEFAULT_NOTIFICATION_CHANNEL_DESCRIPTION", 16, "com_braze_default_notification_channel_description");
        b bVar18 = new b("PUSH_DEEP_LINK_BACK_STACK_ACTIVITY_ENABLED_KEY", 17, "com_braze_push_deep_link_back_stack_activity_enabled");
        b bVar19 = new b("PUSH_DEEP_LINK_BACK_STACK_ACTIVITY_CLASS_NAME_KEY", 18, "com_braze_push_deep_link_back_stack_activity_class_name");
        b bVar20 = new b("SESSION_START_BASED_TIMEOUT_ENABLED_KEY", 19, "com_braze_session_start_based_timeout_enabled");
        b bVar21 = new b("FIREBASE_CLOUD_MESSAGING_REGISTRATION_ENABLED_KEY", 20, "com_braze_firebase_cloud_messaging_registration_enabled");
        b bVar22 = new b("FIREBASE_CLOUD_MESSAGING_SENDER_ID_KEY", 21, "com_braze_firebase_cloud_messaging_sender_id");
        b bVar23 = new b("CONTENT_CARDS_UNREAD_VISUAL_INDICATOR_ENABLED", 22, "com_braze_content_cards_unread_visual_indicator_enabled");
        b bVar24 = new b("DEVICE_OBJECT_ALLOWLISTING_ENABLED_KEY", 23, "com_braze_device_object_whitelisting_enabled");
        b bVar25 = new b("DEVICE_OBJECT_ALLOWLIST_VALUE", 24, "com_braze_device_object_whitelist");
        b = bVar25;
        b bVar26 = new b("IN_APP_MESSAGE_ACCESSIBILITY_EXCLUSIVE_MODE_ENABLED", 25, "com_braze_device_in_app_message_accessibility_exclusive_mode_enabled");
        b bVar27 = new b("PUSH_WAKE_SCREEN_FOR_NOTIFICATION_ENABLED", 26, "com_braze_push_wake_screen_for_notification_enabled");
        b bVar28 = new b("PUSH_NOTIFICATION_HTML_RENDERING_ENABLED", 27, "com_braze_push_notification_html_rendering_enabled");
        b bVar29 = new b("DOES_PUSH_STORY_DISMISS_ON_CLICK", 28, "com_braze_does_push_story_dismiss_on_click");
        b bVar30 = new b("GEOFENCES_ENABLED", 29, "com_braze_geofences_enabled");
        b bVar31 = new b("IN_APP_MESSAGE_PUSH_TEST_EAGER_DISPLAY", 30, "com_braze_in_app_message_push_test_eager_display_enabled");
        b bVar32 = new b("LOGGER_INITIAL_LOG_LEVEL", 31, "com_braze_logger_initial_log_level");
        b bVar33 = new b("CUSTOM_HTML_WEBVIEW_ACTIVITY_CLASS_NAME_KEY", 32, "com_braze_custom_html_webview_activity_class_name");
        b bVar34 = new b("GEOFENCES_AUTOMATIC_REQUESTS_ENABLED_KEY", 33, "com_braze_automatic_geofence_requests_enabled");
        b bVar35 = new b("CUSTOM_LOCATION_PROVIDERS_LIST_KEY", 34, "com_braze_custom_location_providers_list");
        c = bVar35;
        b[] bVarArr = {bVar, bVar2, bVar3, bVar4, bVar5, bVar6, bVar7, bVar8, bVar9, bVar10, bVar11, bVar12, bVar13, bVar14, bVar15, bVar16, bVar17, bVar18, bVar19, bVar20, bVar21, bVar22, bVar23, bVar24, bVar25, bVar26, bVar27, bVar28, bVar29, bVar30, bVar31, bVar32, bVar33, bVar34, bVar35, new b("IN_APP_MESSAGE_WEBVIEW_CLIENT_MAX_ONPAGEFINISHED_WAIT_KEY", 35, "com_braze_in_app_message_webview_client_max_onpagefinished_wait_ms"), new b("FIREBASE_MESSAGING_SERVICE_AUTOMATICALLY_REGISTER_ON_NEW_TOKEN_KEY", 36, "com_braze_firebase_messaging_service_automatically_register_on_new_token"), new b("SDK_AUTH_ENABLED", 37, "com_braze_sdk_authentication_enabled"), new b("REQUIRE_TOUCH_MODE_FOR_HTML_IAMS_KEY", 38, "com_braze_require_touch_mode_for_html_in_app_messages"), new b("DATA_SYNC_BAD_NETWORK_INTERVAL_KEY", 39, "com_braze_data_flush_interval_bad_network"), new b("DATA_SYNC_GOOD_NETWORK_INTERVAL_KEY", 40, "com_braze_data_flush_interval_good_network"), new b("DATA_SYNC_GREAT_NETWORK_INTERVAL_KEY", 41, "com_braze_data_flush_interval_great_network"), new b("FALLBACK_FCM_SERVICE_ENABLED", 42, "com_braze_fallback_firebase_cloud_messaging_service_enabled"), new b("FALLBACK_FCM_SERVICE_CLASSPATH", 43, "com_braze_fallback_firebase_cloud_messaging_service_classpath"), new b("OPTIN_WHEN_PUSH_AUTHORIZED", 44, "com_braze_optin_when_push_authorized"), new b("PERSIST_IAM_WEBVIEW_WHEN_BACKGROUNDING_APP", 45, "com_braze_persist_webview_when_backgrounding_app"), new b("SDK_METADATA_INTERNAL_KEY", 46, "com_braze_internal_sdk_metadata"), new b("SDK_METADATA_PUBLIC_KEY", 47, "com_braze_sdk_metadata"), new b("HTML_IN_APP_MESSAGE_APPLY_WINDOW_INSETS", 48, "com_braze_html_in_app_message_apply_insets"), new b("HTML_IN_APP_MESSAGE_ENABLE_HTML_LINK_TARGET", 49, "com_braze_html_in_app_message_enable_html_link_target"), new b("USE_WINDOW_FLAG_SECURE_IN_ACTIVITIES", 50, "com_braze_use_activity_window_flag_secure"), new b("IN_APP_MESSAGE_ADD_STATUS_BAR_PADDING_KEY", 51, "com_braze_in_app_message_add_status_bar_padding")};
        d = bVarArr;
        AbstractC3328d.f(bVarArr);
    }

    public b(String str, int i, String str2) {
        this.a = str2;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) d.clone();
    }
}
