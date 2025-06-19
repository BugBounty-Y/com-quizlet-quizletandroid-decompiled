package com.skydoves.balloon;

import android.view.MotionEvent;
import android.view.View;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface OnBalloonOutsideTouchListener {
    void onBalloonOutsideTouch(@NotNull View view, @NotNull MotionEvent motionEvent);
}
