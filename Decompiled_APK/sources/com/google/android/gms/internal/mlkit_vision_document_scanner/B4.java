package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.view.MotionEvent;
import android.widget.Button;
import com.perimeterx.mobile_sdk.doctor_app.ui.PXDoctorActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class B4 {
    public static final /* synthetic */ int a = 0;

    public static void a(Button button, MotionEvent event, PXDoctorActivity context, Integer num, Integer num2, Bitmap bitmap, Bitmap bitmap2) {
        Intrinsics.checkNotNullParameter(button, "button");
        Intrinsics.checkNotNullParameter(event, "event");
        Intrinsics.checkNotNullParameter(context, "context");
        int action = event.getAction();
        if (action == 0) {
            iIntValue = num2 != null ? num2.intValue() : 0;
            bitmap = bitmap2;
        } else if (action != 1 && action != 3) {
            bitmap = null;
        } else if (num != null) {
            iIntValue = num.intValue();
        }
        if (iIntValue != 0) {
            button.setTextColor(context.getColor(iIntValue));
        }
        if (bitmap != null) {
            button.setBackground(new BitmapDrawable(context.getResources(), bitmap));
        }
    }
}
