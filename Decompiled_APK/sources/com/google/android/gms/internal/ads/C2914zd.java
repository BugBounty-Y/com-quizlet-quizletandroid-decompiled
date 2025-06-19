package com.google.android.gms.internal.ads;

import android.content.Context;
import android.hardware.SensorEvent;
import android.hardware.SensorManager;
import android.view.Display;
import android.view.WindowManager;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: com.google.android.gms.internal.ads.zd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2914zd extends Ms {
    public final SensorManager a;
    public final Display c;
    public float[] f;
    public Ls g;
    public C1662Ad h;
    public final float[] d = new float[9];
    public final float[] e = new float[9];
    public final Object b = new Object();

    public C2914zd(Context context) {
        this.a = (SensorManager) context.getSystemService("sensor");
        this.c = ((WindowManager) context.getSystemService("window")).getDefaultDisplay();
    }

    @Override // com.google.android.gms.internal.ads.Ms
    public final void a(SensorEvent sensorEvent) {
        float[] fArr = sensorEvent.values;
        if (fArr[0] == DefinitionKt.NO_Float_VALUE && fArr[1] == DefinitionKt.NO_Float_VALUE && fArr[2] == DefinitionKt.NO_Float_VALUE) {
            return;
        }
        synchronized (this.b) {
            try {
                if (this.f == null) {
                    this.f = new float[9];
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        float[] fArr2 = this.d;
        SensorManager.getRotationMatrixFromVector(fArr2, fArr);
        int rotation = this.c.getRotation();
        if (rotation == 1) {
            SensorManager.remapCoordinateSystem(fArr2, 2, 129, this.e);
        } else if (rotation == 2) {
            SensorManager.remapCoordinateSystem(fArr2, 129, 130, this.e);
        } else if (rotation != 3) {
            System.arraycopy(fArr2, 0, this.e, 0, 9);
        } else {
            SensorManager.remapCoordinateSystem(fArr2, 130, 1, this.e);
        }
        float[] fArr3 = this.e;
        float f = fArr3[1];
        fArr3[1] = fArr3[3];
        fArr3[3] = f;
        float f2 = fArr3[2];
        fArr3[2] = fArr3[6];
        fArr3[6] = f2;
        float f3 = fArr3[5];
        fArr3[5] = fArr3[7];
        fArr3[7] = f3;
        synchronized (this.b) {
            System.arraycopy(fArr3, 0, this.f, 0, 9);
        }
        C1662Ad c1662Ad = this.h;
        if (c1662Ad != null) {
            Object obj = c1662Ad.u;
            synchronized (obj) {
                obj.notifyAll();
            }
        }
    }

    public final void b() {
        if (this.g == null) {
            return;
        }
        this.a.unregisterListener(this);
        this.g.post(new C4(2));
        this.g = null;
    }

    public final boolean c(float[] fArr) {
        synchronized (this.b) {
            try {
                float[] fArr2 = this.f;
                if (fArr2 == null) {
                    return false;
                }
                System.arraycopy(fArr2, 0, fArr, 0, 9);
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
