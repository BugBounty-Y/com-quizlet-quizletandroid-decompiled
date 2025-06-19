package com.braze.ui.inappmessage.factories;

import android.view.View;
import android.view.animation.Animation;
import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.models.inappmessage.IInAppMessage;
import com.braze.ui.inappmessage.DefaultInAppMessageViewWrapper;
import com.braze.ui.inappmessage.IInAppMessageViewWrapper;
import com.braze.ui.inappmessage.IInAppMessageViewWrapperFactory;
import com.braze.ui.inappmessage.listeners.IInAppMessageViewLifecycleListener;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class DefaultInAppMessageViewWrapperFactory implements IInAppMessageViewWrapperFactory {
    @Override // com.braze.ui.inappmessage.IInAppMessageViewWrapperFactory
    @NotNull
    public IInAppMessageViewWrapper createInAppMessageViewWrapper(@NotNull View inAppMessageView, @NotNull IInAppMessage inAppMessage, @NotNull IInAppMessageViewLifecycleListener inAppMessageViewLifecycleListener, @NotNull BrazeConfigurationProvider configurationProvider, Animation animation, Animation animation2, View view) {
        Intrinsics.checkNotNullParameter(inAppMessageView, "inAppMessageView");
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
        Intrinsics.checkNotNullParameter(inAppMessageViewLifecycleListener, "inAppMessageViewLifecycleListener");
        Intrinsics.checkNotNullParameter(configurationProvider, "configurationProvider");
        return new DefaultInAppMessageViewWrapper(inAppMessageView, inAppMessage, inAppMessageViewLifecycleListener, configurationProvider, animation, animation2, view, null, null, 384, null);
    }

    @Override // com.braze.ui.inappmessage.IInAppMessageViewWrapperFactory
    @NotNull
    public IInAppMessageViewWrapper createInAppMessageViewWrapper(@NotNull View inAppMessageView, @NotNull IInAppMessage inAppMessage, @NotNull IInAppMessageViewLifecycleListener inAppMessageViewLifecycleListener, @NotNull BrazeConfigurationProvider configurationProvider, Animation animation, Animation animation2, View view, List<? extends View> list, View view2) {
        Intrinsics.checkNotNullParameter(inAppMessageView, "inAppMessageView");
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
        Intrinsics.checkNotNullParameter(inAppMessageViewLifecycleListener, "inAppMessageViewLifecycleListener");
        Intrinsics.checkNotNullParameter(configurationProvider, "configurationProvider");
        return new DefaultInAppMessageViewWrapper(inAppMessageView, inAppMessage, inAppMessageViewLifecycleListener, configurationProvider, animation, animation2, view, list, view2);
    }
}
