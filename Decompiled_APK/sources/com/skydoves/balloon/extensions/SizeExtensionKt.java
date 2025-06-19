package com.skydoves.balloon.extensions;

import android.content.res.Resources;
import android.graphics.Point;
import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public final class SizeExtensionKt {
    public static final /* synthetic */ Point getDisplaySize() {
        return new Point(Resources.getSystem().getDisplayMetrics().widthPixels, Resources.getSystem().getDisplayMetrics().heightPixels);
    }
}
