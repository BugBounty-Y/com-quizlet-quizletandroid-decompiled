package com.google.android.gms.internal.ads;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorManager;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: com.google.android.gms.internal.ads.fl, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2062fl extends Ms {
    public final SensorManager a;
    public final Sensor b;
    public float c = DefinitionKt.NO_Float_VALUE;
    public Float d = Float.valueOf(DefinitionKt.NO_Float_VALUE);
    public long e;
    public int f;
    public boolean g;
    public boolean h;
    public C2493pl i;
    public boolean j;

    public C2062fl(Context context) {
        com.google.android.gms.ads.internal.j.C.k.getClass();
        this.e = System.currentTimeMillis();
        this.f = 0;
        this.g = false;
        this.h = false;
        this.i = null;
        this.j = false;
        SensorManager sensorManager = (SensorManager) context.getSystemService("sensor");
        this.a = sensorManager;
        if (sensorManager != null) {
            this.b = sensorManager.getDefaultSensor(4);
        } else {
            this.b = null;
        }
    }

    @Override // com.google.android.gms.internal.ads.Ms
    public final void a(SensorEvent sensorEvent) {
        C2601s7 c2601s7 = AbstractC2773w7.d9;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            com.google.android.gms.ads.internal.j.C.k.getClass();
            long jCurrentTimeMillis = System.currentTimeMillis();
            long j = this.e;
            C2601s7 c2601s72 = AbstractC2773w7.f9;
            SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
            if (j + ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).intValue() < jCurrentTimeMillis) {
                this.f = 0;
                this.e = jCurrentTimeMillis;
                this.g = false;
                this.h = false;
                this.c = this.d.floatValue();
            }
            float fFloatValue = this.d.floatValue() + (sensorEvent.values[1] * 4.0f);
            this.d = Float.valueOf(fFloatValue);
            float f = this.c;
            C2601s7 c2601s73 = AbstractC2773w7.e9;
            if (fFloatValue > ((Float) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s73)).floatValue() + f) {
                this.c = this.d.floatValue();
                this.h = true;
            } else if (this.d.floatValue() < this.c - ((Float) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s73)).floatValue()) {
                this.c = this.d.floatValue();
                this.g = true;
            }
            if (this.d.isInfinite()) {
                this.d = Float.valueOf(DefinitionKt.NO_Float_VALUE);
                this.c = DefinitionKt.NO_Float_VALUE;
            }
            if (this.g && this.h) {
                com.google.android.gms.ads.internal.util.A.l("Flick detected.");
                this.e = jCurrentTimeMillis;
                int i = this.f + 1;
                this.f = i;
                this.g = false;
                this.h = false;
                C2493pl c2493pl = this.i;
                if (c2493pl == null || i != ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.g9)).intValue()) {
                    return;
                }
                c2493pl.d(new BinderC2364ml(1), EnumC2450ol.c);
            }
        }
    }

    public final void b() {
        SensorManager sensorManager;
        Sensor sensor;
        synchronized (this) {
            try {
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.d9)).booleanValue()) {
                    if (!this.j && (sensorManager = this.a) != null && (sensor = this.b) != null) {
                        sensorManager.registerListener(this, sensor, 2);
                        this.j = true;
                        com.google.android.gms.ads.internal.util.A.l("Listening for flick gestures.");
                    }
                    if (this.a == null || this.b == null) {
                        com.google.android.gms.ads.internal.util.client.i.h("Flick detection failed to initialize. Failed to obtain gyroscope.");
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
