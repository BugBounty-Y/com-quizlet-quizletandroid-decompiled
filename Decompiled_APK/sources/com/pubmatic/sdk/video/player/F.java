package com.pubmatic.sdk.video.player;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.drawable.GradientDrawable;
import android.os.Handler;
import android.text.TextUtils;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public abstract class F {
    @NonNull
    public static FrameLayout.LayoutParams a(@NonNull Context context, int i, int i2) throws Resources.NotFoundException {
        int dimensionPixelOffset = context.getResources().getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_mute_button_left_margin);
        int dimensionPixelOffset2 = context.getResources().getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_mute_button_bottom_margin);
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(com.pubmatic.sdk.common.utility.o.convertDpToPixel(i), com.pubmatic.sdk.common.utility.o.convertDpToPixel(i2));
        layoutParams.leftMargin = dimensionPixelOffset;
        layoutParams.topMargin = dimensionPixelOffset2;
        return layoutParams;
    }

    public static void b(@NonNull View view, int i) {
        if (view.getVisibility() != 0) {
            view.setVisibility(0);
            view.animate().alpha(1.0f).setDuration(i);
        }
    }

    @NonNull
    public static TextView a(@NonNull Context context, int i, String str, int i2) {
        Resources resources = context.getResources();
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-2, resources.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_control_height));
        layoutParams.gravity = 8388693;
        layoutParams.bottomMargin = resources.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_learn_more_bottom_margin);
        layoutParams.rightMargin = resources.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_learn_more_right_margin);
        TextView textViewCreateTextView = com.pubmatic.sdk.webrendering.a.createTextView(context, str, resources.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_text_size), i);
        GradientDrawable gradientDrawable = new GradientDrawable();
        gradientDrawable.setShape(0);
        gradientDrawable.setCornerRadius(resources.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_learn_more_radius));
        gradientDrawable.setColor(i2);
        gradientDrawable.setStroke(resources.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_control_stroke_width), resources.getColor(com.pubmatic.sdk.video.e.pob_controls_stroke_color));
        gradientDrawable.setAlpha(resources.getInteger(com.pubmatic.sdk.video.i.pob_controls_alpha));
        textViewCreateTextView.setBackground(gradientDrawable);
        int i3 = layoutParams.rightMargin;
        textViewCreateTextView.setPadding(i3, 0, i3, 0);
        textViewCreateTextView.setMaxWidth(resources.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_learn_more_width_max));
        textViewCreateTextView.setMaxLines(1);
        textViewCreateTextView.setEllipsize(TextUtils.TruncateAt.END);
        textViewCreateTextView.setLayoutParams(layoutParams);
        return textViewCreateTextView;
    }

    public static void a(@NonNull View view, int i) {
        if (view.getVisibility() == 0) {
            long j = i;
            view.animate().alpha(DefinitionKt.NO_Float_VALUE).setDuration(j);
            new Handler().postDelayed(new E(view), j);
        }
    }
}
