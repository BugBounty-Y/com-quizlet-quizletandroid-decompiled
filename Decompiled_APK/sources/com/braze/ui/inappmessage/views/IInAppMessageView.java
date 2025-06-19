package com.braze.ui.inappmessage.views;

import android.view.View;
import androidx.core.view.D0;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public interface IInAppMessageView {
    void applyWindowInsets(@NotNull D0 d0);

    boolean getHasAppliedWindowInsets();

    View getMessageClickableView();
}
