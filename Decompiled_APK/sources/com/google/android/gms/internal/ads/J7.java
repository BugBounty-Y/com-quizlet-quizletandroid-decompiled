package com.google.android.gms.internal.ads;

import android.view.MotionEvent;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.concurrent.ScheduledExecutorService;

/* loaded from: classes2.dex */
public final class J7 {
    public MotionEvent a = MotionEvent.obtain(0, 0, 1, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0);
    public MotionEvent b = MotionEvent.obtain(0, 0, 0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0);
    public final ScheduledExecutorService c;

    public J7(ScheduledExecutorService scheduledExecutorService) {
        this.c = scheduledExecutorService;
    }
}
