package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Build;
import android.os.Bundle;
import android.os.Parcelable;
import androidx.activity.AbstractC0037i;
import androidx.activity.result.ActivityResult;
import androidx.camera.camera2.internal.AbstractC0147y;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.l6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3197l6 {
    public static final /* synthetic */ int a = 0;

    public static Object a(Bundle bundle, String str) {
        if (Build.VERSION.SDK_INT >= 34) {
            return AbstractC0037i.b(bundle, str);
        }
        Parcelable parcelable = bundle.getParcelable(str);
        if (ActivityResult.class.isInstance(parcelable)) {
            return parcelable;
        }
        return null;
    }

    public static final void b(com.quizlet.baseui.base.b bVar, String... extras) {
        Intrinsics.checkNotNullParameter(bVar, "<this>");
        Intrinsics.checkNotNullParameter(extras, "extras");
        for (String str : extras) {
            if (!bVar.getIntent().hasExtra(str)) {
                throw new IllegalStateException(AbstractC0147y.d("Activity launched without required extra: ", str));
            }
        }
    }
}
