package com.perimeterx.mobile_sdk.detections.device.motion_interception;

import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C4975b0;
import kotlinx.coroutines.E;
import kotlinx.coroutines.channels.h;

/* loaded from: classes2.dex */
public final class g implements SensorEventListener {
    public static final g a = new g();
    public static final kotlinx.coroutines.internal.d b;
    public static SensorManager c;
    public static final float[] d;
    public static final float[] e;
    public static final float[] f;
    public static final float[] g;
    public static final HashMap h;
    public static final kotlinx.coroutines.sync.c i;
    public static h j;

    static {
        ExecutorService executorServiceNewFixedThreadPool = Executors.newFixedThreadPool(5);
        Intrinsics.checkNotNullExpressionValue(executorServiceNewFixedThreadPool, "newFixedThreadPool(...)");
        b = E.c(new C4975b0(executorServiceNewFixedThreadPool));
        d = new float[3];
        e = new float[3];
        f = new float[9];
        g = new float[3];
        h = new HashMap();
        i = kotlinx.coroutines.sync.d.a();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(kotlin.coroutines.jvm.internal.c r15) {
        /*
            Method dump skipped, instructions count: 235
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.detections.device.motion_interception.g.a(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static void b() {
        if (c == null || j != null) {
            return;
        }
        j = D1.a(50, 6, null);
        E.A(b, null, null, new b(2, 0, null), 3);
        SensorManager sensorManager = c;
        if (sensorManager == null) {
            Intrinsics.m("sensorManager");
            throw null;
        }
        Sensor defaultSensor = sensorManager.getDefaultSensor(1);
        g gVar = a;
        if (defaultSensor != null) {
            SensorManager sensorManager2 = c;
            if (sensorManager2 == null) {
                Intrinsics.m("sensorManager");
                throw null;
            }
            sensorManager2.registerListener(gVar, defaultSensor, 3, 2);
        }
        SensorManager sensorManager3 = c;
        if (sensorManager3 == null) {
            Intrinsics.m("sensorManager");
            throw null;
        }
        Sensor defaultSensor2 = sensorManager3.getDefaultSensor(2);
        if (defaultSensor2 != null) {
            SensorManager sensorManager4 = c;
            if (sensorManager4 != null) {
                sensorManager4.registerListener(gVar, defaultSensor2, 3, 2);
            } else {
                Intrinsics.m("sensorManager");
                throw null;
            }
        }
    }

    public final void c() {
        SensorManager sensorManager = c;
        if (sensorManager == null) {
            return;
        }
        sensorManager.unregisterListener(this);
        h hVar = j;
        if (hVar != null) {
            hVar.i(null);
        }
        j = null;
    }

    @Override // android.hardware.SensorEventListener
    public final void onAccuracyChanged(Sensor sensor, int i2) {
    }

    @Override // android.hardware.SensorEventListener
    public final void onSensorChanged(SensorEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        E.A(b, null, null, new d(event, null, 0), 3);
    }
}
