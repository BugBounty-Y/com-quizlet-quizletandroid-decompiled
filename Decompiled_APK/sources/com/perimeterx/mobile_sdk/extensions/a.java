package com.perimeterx.mobile_sdk.extensions;

import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import androidx.constraintlayout.core.widgets.analyzer.f;
import com.google.android.gms.internal.mlkit_common.u;
import com.perimeterx.mobile_sdk.doctor_app.model.c;
import com.perimeterx.mobile_sdk.doctor_app.ui.PXDoctorActivity;

/* loaded from: classes2.dex */
public final class a implements SensorEventListener {
    public u a;
    public long b;
    public int c;

    @Override // android.hardware.SensorEventListener
    public final void onAccuracyChanged(Sensor sensor, int i) {
    }

    @Override // android.hardware.SensorEventListener
    public final void onSensorChanged(SensorEvent sensorEvent) {
        f fVar;
        com.perimeterx.mobile_sdk.doctor_app.state.a aVarB;
        if (sensorEvent == null) {
            return;
        }
        try {
            float[] fArr = sensorEvent.values;
            float f = fArr[0] / 9.80665f;
            float f2 = fArr[1] / 9.80665f;
            float f3 = fArr[2] / 9.80665f;
            if (((float) Math.sqrt((f3 * f3) + (f2 * f2) + (f * f))) > 1.7f) {
                long jCurrentTimeMillis = System.currentTimeMillis();
                long j = this.b;
                if (400 + j > jCurrentTimeMillis) {
                    return;
                }
                if (j + 1500 < jCurrentTimeMillis) {
                    this.c = 0;
                }
                this.b = jCurrentTimeMillis;
                int i = this.c + 1;
                this.c = i;
                if (i > 0) {
                    this.c = 0;
                    if (this.a == null || (fVar = PXDoctorActivity.h) == null || fVar.b || (aVarB = ((c) fVar.h).a().b()) == null) {
                        return;
                    }
                    fVar.b(aVarB);
                }
            }
        } catch (Exception unused) {
        }
    }
}
