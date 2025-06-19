package androidx.constraintlayout.motion.widget;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import java.util.LinkedHashMap;

/* loaded from: classes.dex */
public final class s implements Comparable {
    public static final String[] r = {"position", "x", "y", OTUXParamsKeys.OT_UX_WIDTH, OTUXParamsKeys.OT_UX_HEIGHT, "pathRotate"};
    public androidx.constraintlayout.core.motion.utils.e a;
    public float c;
    public float d;
    public float e;
    public float f;
    public float g;
    public float h;
    public int b = 0;
    public float i = Float.NaN;
    public int j = -1;
    public int k = -1;
    public float l = Float.NaN;
    public j m = null;
    public LinkedHashMap n = new LinkedHashMap();
    public int o = 0;
    public double[] p = new double[18];
    public double[] q = new double[18];

    public static boolean b(float f, float f2) {
        return (Float.isNaN(f) || Float.isNaN(f2)) ? Float.isNaN(f) != Float.isNaN(f2) : Math.abs(f - f2) > 1.0E-6f;
    }

    public final void a(androidx.constraintlayout.widget.j jVar) {
        int iK;
        this.a = androidx.constraintlayout.core.motion.utils.e.d(jVar.c.d);
        androidx.constraintlayout.widget.l lVar = jVar.c;
        this.j = lVar.e;
        this.k = lVar.b;
        this.i = lVar.h;
        this.b = lVar.f;
        this.l = jVar.d.C;
        for (String str : jVar.f.keySet()) {
            androidx.constraintlayout.widget.b bVar = (androidx.constraintlayout.widget.b) jVar.f.get(str);
            if (bVar != null && (iK = AbstractC0147y.k(bVar.c)) != 4 && iK != 5 && iK != 7) {
                this.n.put(str, bVar);
            }
        }
    }

    public final void c(float f, float f2, float f3, float f4) {
        this.e = f;
        this.f = f2;
        this.g = f3;
        this.h = f4;
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        return Float.compare(this.d, ((s) obj).d);
    }

    public final void d(j jVar, s sVar) {
        double d = (((this.g / 2.0f) + this.e) - sVar.e) - (sVar.g / 2.0f);
        double d2 = (((this.h / 2.0f) + this.f) - sVar.f) - (sVar.h / 2.0f);
        this.m = jVar;
        this.e = (float) Math.hypot(d2, d);
        if (Float.isNaN(this.l)) {
            this.f = (float) (Math.atan2(d2, d) + 1.5707963267948966d);
        } else {
            this.f = (float) Math.toRadians(this.l);
        }
    }
}
