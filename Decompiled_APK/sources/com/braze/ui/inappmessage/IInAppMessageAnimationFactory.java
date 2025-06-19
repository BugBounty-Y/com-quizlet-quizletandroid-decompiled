package com.braze.ui.inappmessage;

import android.view.animation.Animation;
import com.braze.models.inappmessage.IInAppMessage;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public interface IInAppMessageAnimationFactory {
    Animation getClosingAnimation(@NotNull IInAppMessage iInAppMessage);

    Animation getOpeningAnimation(@NotNull IInAppMessage iInAppMessage);
}
