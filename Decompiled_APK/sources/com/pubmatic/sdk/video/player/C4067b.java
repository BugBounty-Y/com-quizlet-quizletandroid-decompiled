package com.pubmatic.sdk.video.player;

import android.R;
import android.view.View;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;

/* renamed from: com.pubmatic.sdk.video.player.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class C4067b {
    public static void updateEndCardView(@NonNull View view, @NonNull View view2, @NonNull com.pubmatic.sdk.common.base.c cVar) {
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(Math.min(com.pubmatic.sdk.common.utility.o.convertDpToPixel(cVar.getContentWidth()), view2.getWidth()), Math.min(com.pubmatic.sdk.common.utility.o.convertDpToPixel(cVar.getContentHeight()), view2.getHeight()));
        layoutParams.gravity = 17;
        view.setLayoutParams(layoutParams);
        view.setBackgroundColor(view2.getResources().getColor(R.color.white));
    }
}
