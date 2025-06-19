package com.pubmatic.sdk.webrendering;

import android.R;
import android.content.Context;
import android.content.res.Resources;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.InsetDrawable;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.TextView;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;

/* loaded from: classes2.dex */
public class a {
    @NonNull
    private static InsetDrawable a(@NonNull Context context) {
        GradientDrawable gradientDrawable = new GradientDrawable();
        gradientDrawable.setShape(1);
        Resources resources = context.getResources();
        gradientDrawable.setColor(resources.getColor(b.pob_controls_background_color));
        gradientDrawable.setStroke(resources.getDimensionPixelOffset(c.pob_control_stroke_width), resources.getColor(b.pob_controls_stroke_color));
        gradientDrawable.setAlpha(resources.getInteger(f.pob_controls_alpha));
        return new InsetDrawable((Drawable) gradientDrawable, resources.getDimensionPixelOffset(c.pob_control_padding));
    }

    @NonNull
    public static ImageButton createSkipButton(@NonNull Context context, int i, int i2) {
        ImageButton imageButton = new ImageButton(context);
        imageButton.setId(i);
        Resources resources = context.getResources();
        imageButton.setBackground(a(context));
        imageButton.setPadding(0, 0, 0, 0);
        imageButton.setImageResource(i2);
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(resources.getDimensionPixelOffset(c.pob_control_width), resources.getDimensionPixelOffset(c.pob_control_height));
        layoutParams.gravity = 8388613;
        layoutParams.rightMargin = resources.getDimensionPixelOffset(c.pob_close_button_right_margin);
        layoutParams.topMargin = resources.getDimensionPixelOffset(c.pob_close_button_top_margin);
        imageButton.setLayoutParams(layoutParams);
        return imageButton;
    }

    @NonNull
    public static TextView createSkipDurationTextView(@NonNull Context context, int i) {
        TextView textViewCreateTextView = createTextView(context, "", context.getResources().getDimensionPixelOffset(c.pob_text_size), i);
        textViewCreateTextView.setBackground(a(context));
        textViewCreateTextView.setPadding(0, 0, 0, 0);
        return textViewCreateTextView;
    }

    @NonNull
    public static TextView createTextView(@NonNull Context context, String str, float f, int i) {
        TextView textView = new TextView(context);
        textView.setAllCaps(false);
        textView.setGravity(17);
        textView.setTextColor(context.getResources().getColor(R.color.white));
        textView.setTextSize(0, f);
        textView.setTextAlignment(4);
        textView.setText(str);
        try {
            textView.setTypeface(Typeface.SANS_SERIF, 1);
        } catch (Exception unused) {
            POBLog.warn("POBUIUtil", "SANS_SERIF font not found!", new Object[0]);
        }
        textView.setId(i);
        return textView;
    }

    @NonNull
    public static FrameLayout.LayoutParams getLayoutParamsForTopRightPosition(@NonNull Context context) {
        Resources resources = context.getResources();
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(resources.getDimensionPixelOffset(c.pob_control_width), resources.getDimensionPixelOffset(c.pob_control_height));
        layoutParams.gravity = 8388613;
        layoutParams.rightMargin = resources.getDimensionPixelOffset(c.pob_skip_control_right_margin);
        layoutParams.topMargin = resources.getDimensionPixelOffset(c.pob_skip_control_top_margin);
        return layoutParams;
    }

    @NonNull
    public static String getLocalizedStringForKey(@NonNull Context context, @NonNull String str, @NonNull String str2) throws Resources.NotFoundException {
        Resources resources = context.getResources();
        int identifier = resources.getIdentifier(str, "string", context.getPackageName());
        if (identifier != 0) {
            String string = resources.getString(identifier);
            if (!string.isEmpty()) {
                return string;
            }
        }
        return str2;
    }

    public static void updateSkipButtonToCloseButton(@NonNull ImageButton imageButton) {
        imageButton.setImageResource(d.pob_ic_close_black_24dp);
        imageButton.setId(e.pob_close_btn);
    }
}
