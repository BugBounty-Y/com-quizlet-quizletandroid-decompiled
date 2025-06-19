package androidx.constraintlayout.core.state;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;

/* loaded from: classes.dex */
public final class f {
    public static final String h = new String("FIXED_DIMENSION");
    public static final String i = new String("WRAP_DIMENSION");
    public static final String j = new String("SPREAD_DIMENSION");
    public static final String k = new String("PARENT_DIMENSION");
    public static final String l = new String("PERCENT_DIMENSION");
    public static final String m = new String("RATIO_DIMENSION");
    public String f;
    public int a = 0;
    public int b = SubsamplingScaleImageView.TILE_SIZE_AUTO;
    public float c = 1.0f;
    public int d = 0;
    public String e = null;
    public boolean g = false;

    public f(String str) {
        this.f = str;
    }

    public static f b(int i2) {
        f fVar = new f(h);
        fVar.f = null;
        fVar.d = i2;
        return fVar;
    }

    public static f c(String str) {
        f fVar = new f();
        fVar.a = 0;
        fVar.b = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        fVar.c = 1.0f;
        fVar.d = 0;
        fVar.e = null;
        fVar.f = str;
        fVar.g = true;
        return fVar;
    }

    public final void a(androidx.constraintlayout.core.widgets.e eVar, int i2) {
        String str = this.e;
        if (str != null) {
            eVar.K(str);
        }
        androidx.constraintlayout.core.widgets.d dVar = androidx.constraintlayout.core.widgets.d.a;
        androidx.constraintlayout.core.widgets.d dVar2 = androidx.constraintlayout.core.widgets.d.d;
        String str2 = k;
        androidx.constraintlayout.core.widgets.d dVar3 = androidx.constraintlayout.core.widgets.d.b;
        String str3 = l;
        androidx.constraintlayout.core.widgets.d dVar4 = androidx.constraintlayout.core.widgets.d.c;
        String str4 = i;
        if (i2 == 0) {
            if (this.g) {
                eVar.O(dVar4);
                String str5 = this.f;
                eVar.P(this.c, str5 != str4 ? str5 == str3 ? 2 : 0 : 1, this.a, this.b);
                return;
            }
            int i3 = this.a;
            if (i3 > 0) {
                if (i3 < 0) {
                    eVar.e0 = 0;
                } else {
                    eVar.e0 = i3;
                }
            }
            int i4 = this.b;
            if (i4 < Integer.MAX_VALUE) {
                eVar.D[0] = i4;
            }
            String str6 = this.f;
            if (str6 == str4) {
                eVar.O(dVar3);
                return;
            }
            if (str6 == str2) {
                eVar.O(dVar2);
                return;
            } else {
                if (str6 == null) {
                    eVar.O(dVar);
                    eVar.S(this.d);
                    return;
                }
                return;
            }
        }
        if (this.g) {
            eVar.Q(dVar4);
            String str7 = this.f;
            eVar.R(this.c, str7 != str4 ? str7 == str3 ? 2 : 0 : 1, this.a, this.b);
            return;
        }
        int i5 = this.a;
        if (i5 > 0) {
            if (i5 < 0) {
                eVar.f0 = 0;
            } else {
                eVar.f0 = i5;
            }
        }
        int i6 = this.b;
        if (i6 < Integer.MAX_VALUE) {
            eVar.D[1] = i6;
        }
        String str8 = this.f;
        if (str8 == str4) {
            eVar.Q(dVar3);
            return;
        }
        if (str8 == str2) {
            eVar.Q(dVar2);
        } else if (str8 == null) {
            eVar.Q(dVar);
            eVar.N(this.d);
        }
    }
}
