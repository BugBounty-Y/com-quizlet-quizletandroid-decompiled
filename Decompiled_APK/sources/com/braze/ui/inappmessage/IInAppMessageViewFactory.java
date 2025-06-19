package com.braze.ui.inappmessage;

import android.app.Activity;
import android.view.View;
import com.braze.models.inappmessage.IInAppMessage;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public interface IInAppMessageViewFactory {
    View createInAppMessageView(@NotNull Activity activity, @NotNull IInAppMessage iInAppMessage);
}
