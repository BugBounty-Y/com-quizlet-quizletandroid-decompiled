package com.braze.ui.inappmessage.utils;

import android.R;
import android.content.Context;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.graphics.drawable.StateListDrawable;
import android.view.View;
import android.widget.Button;
import com.braze.models.inappmessage.MessageButton;
import com.braze.ui.R$dimen;
import com.braze.ui.R$drawable;
import com.braze.ui.R$id;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class InAppMessageButtonViewUtils {

    @NotNull
    public static final InAppMessageButtonViewUtils INSTANCE = new InAppMessageButtonViewUtils();

    private InAppMessageButtonViewUtils() {
    }

    @NotNull
    public static final Drawable getButtonDrawable(@NotNull Context context, @NotNull MessageButton messageButton, int i, int i2, boolean z) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(messageButton, "messageButton");
        Drawable drawable = getDrawable(context, R$drawable.com_braze_inappmessage_button_background);
        drawable.mutate();
        Drawable drawableFindDrawableByLayerId = ((RippleDrawable) drawable).findDrawableByLayerId(R$id.com_braze_inappmessage_button_background_ripple_internal_gradient);
        Intrinsics.e(drawableFindDrawableByLayerId, "null cannot be cast to non-null type android.graphics.drawable.GradientDrawable");
        GradientDrawable gradientDrawable = (GradientDrawable) drawableFindDrawableByLayerId;
        if (z) {
            i = i2;
        }
        gradientDrawable.setStroke(i, messageButton.getBorderColor());
        gradientDrawable.setColor(messageButton.getBackgroundColor());
        return drawable;
    }

    @NotNull
    public static final Drawable getDrawable(@NotNull Context context, int i) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(context, "context");
        Drawable drawable = context.getResources().getDrawable(i, null);
        Intrinsics.checkNotNullExpressionValue(drawable, "getDrawable(...)");
        return drawable;
    }

    public static final void setButton(@NotNull Button button, @NotNull MessageButton messageButton, int i, int i2) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(button, "button");
        Intrinsics.checkNotNullParameter(messageButton, "messageButton");
        button.setText(messageButton.getText());
        button.setContentDescription(messageButton.getText());
        InAppMessageViewUtils.setTextViewColor(button, messageButton.getTextColor());
        StateListDrawable stateListDrawable = new StateListDrawable();
        button.setStateListAnimator(null);
        Context context = button.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        Drawable buttonDrawable = getButtonDrawable(context, messageButton, i, i2, false);
        Context context2 = button.getContext();
        Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
        stateListDrawable.addState(new int[]{R.attr.state_focused}, getButtonDrawable(context2, messageButton, i, i2, true));
        stateListDrawable.addState(new int[]{R.attr.state_enabled}, buttonDrawable);
        button.setBackground(stateListDrawable);
    }

    public static final void setButtons(@NotNull List<? extends View> buttonViews, @NotNull List<? extends MessageButton> messageButtons) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(buttonViews, "buttonViews");
        Intrinsics.checkNotNullParameter(messageButtons, "messageButtons");
        int size = buttonViews.size();
        for (int i = 0; i < size; i++) {
            View view = buttonViews.get(i);
            MessageButton messageButton = messageButtons.get(i);
            int dimensionPixelSize = view.getContext().getResources().getDimensionPixelSize(R$dimen.com_braze_inappmessage_button_border_stroke);
            int dimensionPixelSize2 = view.getContext().getResources().getDimensionPixelSize(R$dimen.com_braze_inappmessage_button_border_stroke_focused);
            if (messageButtons.size() <= i) {
                view.setVisibility(8);
            } else if (view instanceof Button) {
                setButton((Button) view, messageButton, dimensionPixelSize, dimensionPixelSize2);
            }
        }
    }
}
