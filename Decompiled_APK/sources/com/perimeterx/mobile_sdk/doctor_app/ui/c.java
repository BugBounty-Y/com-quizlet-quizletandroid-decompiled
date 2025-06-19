package com.perimeterx.mobile_sdk.doctor_app.ui;

import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.View;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c implements View.OnTouchListener {
    public final GestureDetector a;
    public final /* synthetic */ PXDoctorActivity b;

    public c(PXDoctorActivity pXDoctorActivity) {
        this.b = pXDoctorActivity;
        this.a = new GestureDetector(pXDoctorActivity, new androidx.camera.view.impl.a(this, 1));
    }

    @Override // android.view.View.OnTouchListener
    public final boolean onTouch(View v, MotionEvent event) {
        Intrinsics.checkNotNullParameter(v, "v");
        Intrinsics.checkNotNullParameter(event, "event");
        return this.a.onTouchEvent(event);
    }
}
