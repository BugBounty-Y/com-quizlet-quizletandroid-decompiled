package com.braze.ui.inappmessage;

import android.app.Activity;
import android.view.View;
import com.braze.models.inappmessage.IInAppMessage;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public interface IInAppMessageViewWrapper {
    void close();

    @NotNull
    IInAppMessage getInAppMessage();

    @NotNull
    View getInAppMessageView();

    boolean isAnimatingClose();

    void open(@NotNull Activity activity);
}
