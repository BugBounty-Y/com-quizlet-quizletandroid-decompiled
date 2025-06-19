package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.x6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3299x6 {
    public static final /* synthetic */ int a = 0;

    public static final boolean a(View itemView, boolean z) {
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        ViewGroup.LayoutParams layoutParams = itemView.getLayoutParams();
        if (!z || !(layoutParams instanceof ViewGroup.MarginLayoutParams)) {
            return false;
        }
        Context context = itemView.getContext();
        int dimension = (int) context.getResources().getDimension(R.dimen.home_horizontal_scroll_end_card_margin);
        int dimension2 = (int) context.getResources().getDimension(R.dimen.home_horizontal_scroll_card_width);
        ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) layoutParams;
        marginLayoutParams.setMarginStart(0);
        marginLayoutParams.setMarginEnd(dimension);
        marginLayoutParams.width = dimension2;
        return true;
    }
}
