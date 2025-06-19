package com.google.android.gms.internal.ads;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorManager;

/* renamed from: com.google.android.gms.internal.ads.vl, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2750vl extends Ms {
    public final Context a;
    public SensorManager b;
    public Sensor c;
    public long d;
    public int e;
    public C2493pl f;
    public boolean g;

    public C2750vl(Context context) {
        this.a = context;
    }

    @Override // com.google.android.gms.internal.ads.Ms
    public final void a(SensorEvent sensorEvent) {
        C2601s7 c2601s7 = AbstractC2773w7.Y8;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            float[] fArr = sensorEvent.values;
            float f = fArr[0] / 9.80665f;
            float f2 = fArr[1] / 9.80665f;
            float f3 = fArr[2] / 9.80665f;
            float f4 = f3 * f3;
            float fSqrt = (float) Math.sqrt(f4 + (f2 * f2) + (f * f));
            C2601s7 c2601s72 = AbstractC2773w7.Z8;
            SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
            if (fSqrt >= ((Float) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).floatValue()) {
                com.google.android.gms.ads.internal.j.C.k.getClass();
                long jCurrentTimeMillis = System.currentTimeMillis();
                if (this.d + ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.a9)).intValue() <= jCurrentTimeMillis) {
                    if (this.d + ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.b9)).intValue() < jCurrentTimeMillis) {
                        this.e = 0;
                    }
                    com.google.android.gms.ads.internal.util.A.l("Shake detected.");
                    this.d = jCurrentTimeMillis;
                    int i = this.e + 1;
                    this.e = i;
                    C2493pl c2493pl = this.f;
                    if (c2493pl == null || i != ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.c9)).intValue()) {
                        return;
                    }
                    c2493pl.d(new BinderC2364ml(0), EnumC2450ol.c);
                }
            }
        }
    }

    public final void b() {
        SensorManager sensorManager;
        Sensor sensor;
        synchronized (this) {
            try {
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Y8)).booleanValue()) {
                    if (this.b == null) {
                        SensorManager sensorManager2 = (SensorManager) this.a.getSystemService("sensor");
                        this.b = sensorManager2;
                        if (sensorManager2 == null) {
                            com.google.android.gms.ads.internal.util.client.i.h("Shake detection failed to initialize. Failed to obtain accelerometer.");
                            return;
                        }
                        this.c = sensorManager2.getDefaultSensor(1);
                    }
                    if (!this.g && (sensorManager = this.b) != null && (sensor = this.c) != null) {
                        sensorManager.registerListener(this, sensor, 2);
                        com.google.android.gms.ads.internal.j.C.k.getClass();
                        this.d = System.currentTimeMillis() - ((Integer) r1.c.a(AbstractC2773w7.a9)).intValue();
                        this.g = true;
                        com.google.android.gms.ads.internal.util.A.l("Listening for shake gestures.");
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
