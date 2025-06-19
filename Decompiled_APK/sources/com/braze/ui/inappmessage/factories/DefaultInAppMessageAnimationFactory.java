package com.braze.ui.inappmessage.factories;

import android.R;
import android.content.res.Resources;
import android.view.animation.AlphaAnimation;
import android.view.animation.Animation;
import com.braze.enums.inappmessage.SlideFrom;
import com.braze.models.inappmessage.IInAppMessage;
import com.braze.models.inappmessage.InAppMessageSlideup;
import com.braze.ui.inappmessage.IInAppMessageAnimationFactory;
import com.braze.ui.support.AnimationUtils;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class DefaultInAppMessageAnimationFactory implements IInAppMessageAnimationFactory {
    private final long shortAnimationDurationMs = Resources.getSystem().getInteger(R.integer.config_shortAnimTime);

    @Override // com.braze.ui.inappmessage.IInAppMessageAnimationFactory
    public Animation getClosingAnimation(@NotNull IInAppMessage inAppMessage) {
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
        return inAppMessage instanceof InAppMessageSlideup ? ((InAppMessageSlideup) inAppMessage).getSlideFrom() == SlideFrom.TOP ? AnimationUtils.createVerticalAnimation(DefinitionKt.NO_Float_VALUE, -1.0f, this.shortAnimationDurationMs, false) : AnimationUtils.createVerticalAnimation(DefinitionKt.NO_Float_VALUE, 1.0f, this.shortAnimationDurationMs, false) : AnimationUtils.setAnimationParams(new AlphaAnimation(1.0f, DefinitionKt.NO_Float_VALUE), this.shortAnimationDurationMs, false);
    }

    @Override // com.braze.ui.inappmessage.IInAppMessageAnimationFactory
    public Animation getOpeningAnimation(@NotNull IInAppMessage inAppMessage) {
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
        return inAppMessage instanceof InAppMessageSlideup ? ((InAppMessageSlideup) inAppMessage).getSlideFrom() == SlideFrom.TOP ? AnimationUtils.createVerticalAnimation(-1.0f, DefinitionKt.NO_Float_VALUE, this.shortAnimationDurationMs, false) : AnimationUtils.createVerticalAnimation(1.0f, DefinitionKt.NO_Float_VALUE, this.shortAnimationDurationMs, false) : AnimationUtils.setAnimationParams(new AlphaAnimation(DefinitionKt.NO_Float_VALUE, 1.0f), this.shortAnimationDurationMs, true);
    }
}
