package androidx.constraintlayout.motion.widget;

import android.graphics.Rect;
import android.util.Log;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.HashMap;
import java.util.LinkedHashMap;

/* loaded from: classes.dex */
public final class h implements Comparable {
    public int c;
    public float a = DefinitionKt.NO_Float_VALUE;
    public int b = 0;
    public final LinkedHashMap d = new LinkedHashMap();
    public float e = 1.0f;
    public float f = DefinitionKt.NO_Float_VALUE;
    public float g = DefinitionKt.NO_Float_VALUE;
    public float h = DefinitionKt.NO_Float_VALUE;
    public float i = 1.0f;
    public float j = 1.0f;
    public float k = Float.NaN;
    public float l = Float.NaN;
    public float m = DefinitionKt.NO_Float_VALUE;
    public float n = DefinitionKt.NO_Float_VALUE;
    public float o = DefinitionKt.NO_Float_VALUE;
    public float p = Float.NaN;
    public float q = Float.NaN;

    public static boolean b(float f, float f2) {
        return (Float.isNaN(f) || Float.isNaN(f2)) ? Float.isNaN(f) != Float.isNaN(f2) : Math.abs(f - f2) > 1.0E-6f;
    }

    public final void a(HashMap map, int i) {
        float f;
        for (String str : map.keySet()) {
            androidx.constraintlayout.motion.utils.k kVar = (androidx.constraintlayout.motion.utils.k) map.get(str);
            if (kVar != null) {
                str.getClass();
                f = DefinitionKt.NO_Float_VALUE;
                switch (str) {
                    case "rotationX":
                        if (!Float.isNaN(this.h)) {
                            f = this.h;
                        }
                        kVar.b(f, i);
                        break;
                    case "rotationY":
                        if (!Float.isNaN(this.a)) {
                            f = this.a;
                        }
                        kVar.b(f, i);
                        break;
                    case "translationX":
                        if (!Float.isNaN(this.m)) {
                            f = this.m;
                        }
                        kVar.b(f, i);
                        break;
                    case "translationY":
                        if (!Float.isNaN(this.n)) {
                            f = this.n;
                        }
                        kVar.b(f, i);
                        break;
                    case "translationZ":
                        if (!Float.isNaN(this.o)) {
                            f = this.o;
                        }
                        kVar.b(f, i);
                        break;
                    case "progress":
                        if (!Float.isNaN(this.q)) {
                            f = this.q;
                        }
                        kVar.b(f, i);
                        break;
                    case "scaleX":
                        kVar.b(Float.isNaN(this.i) ? 1.0f : this.i, i);
                        break;
                    case "scaleY":
                        kVar.b(Float.isNaN(this.j) ? 1.0f : this.j, i);
                        break;
                    case "transformPivotX":
                        if (!Float.isNaN(this.k)) {
                            f = this.k;
                        }
                        kVar.b(f, i);
                        break;
                    case "transformPivotY":
                        if (!Float.isNaN(this.l)) {
                            f = this.l;
                        }
                        kVar.b(f, i);
                        break;
                    case "rotation":
                        if (!Float.isNaN(this.g)) {
                            f = this.g;
                        }
                        kVar.b(f, i);
                        break;
                    case "elevation":
                        if (!Float.isNaN(this.f)) {
                            f = this.f;
                        }
                        kVar.b(f, i);
                        break;
                    case "transitionPathRotate":
                        if (!Float.isNaN(this.p)) {
                            f = this.p;
                        }
                        kVar.b(f, i);
                        break;
                    case "alpha":
                        kVar.b(Float.isNaN(this.e) ? 1.0f : this.e, i);
                        break;
                    default:
                        if (str.startsWith("CUSTOM")) {
                            String str2 = str.split(",")[1];
                            LinkedHashMap linkedHashMap = this.d;
                            if (linkedHashMap.containsKey(str2)) {
                                androidx.constraintlayout.widget.b bVar = (androidx.constraintlayout.widget.b) linkedHashMap.get(str2);
                                if (kVar instanceof androidx.constraintlayout.motion.utils.h) {
                                    ((androidx.constraintlayout.motion.utils.h) kVar).f.append(i, bVar);
                                    break;
                                } else {
                                    Log.e("MotionPaths", str + " ViewSpline not a CustomSet frame = " + i + ", value" + bVar.a() + kVar);
                                    break;
                                }
                            } else {
                                break;
                            }
                        } else {
                            Log.e("MotionPaths", "UNKNOWN spline ".concat(str));
                            break;
                        }
                }
            }
        }
    }

    public final void c(Rect rect, androidx.constraintlayout.widget.o oVar, int i, int i2) {
        rect.width();
        rect.height();
        androidx.constraintlayout.widget.j jVarH = oVar.h(i2);
        androidx.constraintlayout.widget.m mVar = jVarH.b;
        int i3 = mVar.c;
        this.b = i3;
        int i4 = mVar.b;
        this.c = i4;
        this.e = (i4 == 0 || i3 != 0) ? mVar.d : DefinitionKt.NO_Float_VALUE;
        androidx.constraintlayout.widget.n nVar = jVarH.e;
        boolean z = nVar.m;
        this.f = nVar.n;
        this.g = nVar.b;
        this.h = nVar.c;
        this.a = nVar.d;
        this.i = nVar.e;
        this.j = nVar.f;
        this.k = nVar.g;
        this.l = nVar.h;
        this.m = nVar.j;
        this.n = nVar.k;
        this.o = nVar.l;
        androidx.constraintlayout.widget.l lVar = jVarH.c;
        androidx.constraintlayout.core.motion.utils.e.d(lVar.d);
        this.p = lVar.h;
        this.q = jVarH.b.e;
        for (String str : jVarH.f.keySet()) {
            androidx.constraintlayout.widget.b bVar = (androidx.constraintlayout.widget.b) jVarH.f.get(str);
            int iK = AbstractC0147y.k(bVar.c);
            if (iK != 4 && iK != 5 && iK != 7) {
                this.d.put(str, bVar);
            }
        }
        if (i != 1) {
            if (i != 2) {
                if (i != 3) {
                    if (i != 4) {
                        return;
                    }
                }
            }
            float f = this.g + 90.0f;
            this.g = f;
            if (f > 180.0f) {
                this.g = f - 360.0f;
                return;
            }
            return;
        }
        this.g -= 90.0f;
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        ((h) obj).getClass();
        return Float.compare(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
    }
}
