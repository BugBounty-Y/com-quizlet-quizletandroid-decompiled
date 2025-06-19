package com.braze.ui.inappmessage.views;

import android.view.View;
import java.util.List;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public interface IInAppMessageImmersiveView extends IInAppMessageView {
    @NotNull
    List<View> getMessageButtonViews(int i);

    View getMessageCloseButtonView();
}
