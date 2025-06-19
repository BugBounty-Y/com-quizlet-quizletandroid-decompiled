package com.google.android.gms.internal.mlkit_vision_common;

import android.content.res.Configuration;
import android.graphics.Typeface;
import android.os.Build;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.f4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3454f4 {
    public static final /* synthetic */ int a = 0;

    public static Typeface a(Configuration configuration, Typeface typeface) {
        if (Build.VERSION.SDK_INT < 31 || configuration.fontWeightAdjustment == Integer.MAX_VALUE || configuration.fontWeightAdjustment == 0 || typeface == null) {
            return null;
        }
        return Typeface.create(typeface, AbstractC3188k6.b(configuration.fontWeightAdjustment + typeface.getWeight(), 1, 1000), typeface.isItalic());
    }
}
