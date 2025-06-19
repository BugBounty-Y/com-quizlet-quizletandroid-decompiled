package com.braze.ui.inappmessage.listeners;

import android.view.View;
import com.braze.models.inappmessage.IInAppMessage;
import com.braze.models.inappmessage.MessageButton;
import com.braze.support.BrazeFunctionNotImplemented;
import com.braze.ui.inappmessage.InAppMessageCloser;
import com.braze.ui.inappmessage.InAppMessageOperation;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public interface IInAppMessageManagerListener {
    default void afterInAppMessageViewClosed(@NotNull IInAppMessage inAppMessage) {
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
    }

    default void afterInAppMessageViewOpened(@NotNull View inAppMessageView, @NotNull IInAppMessage inAppMessage) {
        Intrinsics.checkNotNullParameter(inAppMessageView, "inAppMessageView");
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
    }

    @NotNull
    InAppMessageOperation beforeInAppMessageDisplayed(@NotNull IInAppMessage iInAppMessage);

    default void beforeInAppMessageViewClosed(@NotNull View inAppMessageView, @NotNull IInAppMessage inAppMessage) {
        Intrinsics.checkNotNullParameter(inAppMessageView, "inAppMessageView");
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
    }

    default void beforeInAppMessageViewOpened(@NotNull View inAppMessageView, @NotNull IInAppMessage inAppMessage) {
        Intrinsics.checkNotNullParameter(inAppMessageView, "inAppMessageView");
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
    }

    default boolean onInAppMessageButtonClicked(@NotNull IInAppMessage inAppMessage, @NotNull MessageButton button) {
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
        Intrinsics.checkNotNullParameter(button, "button");
        return false;
    }

    default boolean onInAppMessageClicked(@NotNull IInAppMessage inAppMessage) {
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
        return false;
    }

    default void onInAppMessageDismissed(@NotNull IInAppMessage inAppMessage) {
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
    }

    @InterfaceC4935d
    default boolean onInAppMessageButtonClicked(@NotNull IInAppMessage inAppMessage, @NotNull MessageButton button, InAppMessageCloser inAppMessageCloser) {
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
        Intrinsics.checkNotNullParameter(button, "button");
        throw BrazeFunctionNotImplemented.INSTANCE;
    }

    @InterfaceC4935d
    default boolean onInAppMessageClicked(@NotNull IInAppMessage inAppMessage, InAppMessageCloser inAppMessageCloser) {
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
        throw BrazeFunctionNotImplemented.INSTANCE;
    }
}
