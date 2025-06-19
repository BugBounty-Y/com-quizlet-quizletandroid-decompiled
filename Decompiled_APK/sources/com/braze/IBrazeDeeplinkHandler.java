package com.braze;

import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import com.braze.enums.Channel;
import com.braze.ui.actions.NewsfeedAction;
import com.braze.ui.actions.UriAction;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public interface IBrazeDeeplinkHandler {

    /* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
    /* JADX WARN: Unknown enum class pattern. Please report as an issue! */
    @Metadata
    public static final class IntentFlagPurpose {
        private static final /* synthetic */ kotlin.enums.a $ENTRIES;
        private static final /* synthetic */ IntentFlagPurpose[] $VALUES;
        public static final IntentFlagPurpose NOTIFICATION_ACTION_WITH_DEEPLINK = new IntentFlagPurpose("NOTIFICATION_ACTION_WITH_DEEPLINK", 0);
        public static final IntentFlagPurpose NOTIFICATION_PUSH_STORY_PAGE_CLICK = new IntentFlagPurpose("NOTIFICATION_PUSH_STORY_PAGE_CLICK", 1);
        public static final IntentFlagPurpose URI_ACTION_OPEN_WITH_WEBVIEW_ACTIVITY = new IntentFlagPurpose("URI_ACTION_OPEN_WITH_WEBVIEW_ACTIVITY", 2);
        public static final IntentFlagPurpose URI_ACTION_OPEN_WITH_ACTION_VIEW = new IntentFlagPurpose("URI_ACTION_OPEN_WITH_ACTION_VIEW", 3);
        public static final IntentFlagPurpose URI_ACTION_BACK_STACK_GET_ROOT_INTENT = new IntentFlagPurpose("URI_ACTION_BACK_STACK_GET_ROOT_INTENT", 4);
        public static final IntentFlagPurpose URI_ACTION_BACK_STACK_ONLY_GET_TARGET_INTENT = new IntentFlagPurpose("URI_ACTION_BACK_STACK_ONLY_GET_TARGET_INTENT", 5);
        public static final IntentFlagPurpose URI_UTILS_GET_MAIN_ACTIVITY_INTENT = new IntentFlagPurpose("URI_UTILS_GET_MAIN_ACTIVITY_INTENT", 6);

        private static final /* synthetic */ IntentFlagPurpose[] $values() {
            return new IntentFlagPurpose[]{NOTIFICATION_ACTION_WITH_DEEPLINK, NOTIFICATION_PUSH_STORY_PAGE_CLICK, URI_ACTION_OPEN_WITH_WEBVIEW_ACTIVITY, URI_ACTION_OPEN_WITH_ACTION_VIEW, URI_ACTION_BACK_STACK_GET_ROOT_INTENT, URI_ACTION_BACK_STACK_ONLY_GET_TARGET_INTENT, URI_UTILS_GET_MAIN_ACTIVITY_INTENT};
        }

        static {
            IntentFlagPurpose[] intentFlagPurposeArr$values = $values();
            $VALUES = intentFlagPurposeArr$values;
            $ENTRIES = AbstractC3328d.f(intentFlagPurposeArr$values);
        }

        private IntentFlagPurpose(String str, int i) {
        }

        public static IntentFlagPurpose valueOf(String str) {
            return (IntentFlagPurpose) Enum.valueOf(IntentFlagPurpose.class, str);
        }

        public static IntentFlagPurpose[] values() {
            return (IntentFlagPurpose[]) $VALUES.clone();
        }
    }

    @NotNull
    UriAction createUriActionFromUri(@NotNull Uri uri, Bundle bundle, boolean z, @NotNull Channel channel);

    UriAction createUriActionFromUrlString(@NotNull String str, Bundle bundle, boolean z, @NotNull Channel channel);

    int getIntentFlags(@NotNull IntentFlagPurpose intentFlagPurpose);

    void gotoNewsFeed(@NotNull Context context, @NotNull NewsfeedAction newsfeedAction);

    void gotoUri(@NotNull Context context, @NotNull UriAction uriAction);
}
