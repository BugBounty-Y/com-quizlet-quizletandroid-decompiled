package androidx.vectordrawable.graphics.drawable;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3152g6;

/* loaded from: classes.dex */
public abstract class l extends k {
    public androidx.core.graphics.g[] a;
    public String b;
    public int c;

    public l() {
        this.a = null;
        this.c = 0;
    }

    public androidx.core.graphics.g[] getPathData() {
        return this.a;
    }

    public String getPathName() {
        return this.b;
    }

    public void setPathData(androidx.core.graphics.g[] gVarArr) {
        androidx.core.graphics.g[] gVarArr2 = this.a;
        boolean z = false;
        if (gVarArr2 != null && gVarArr != null && gVarArr2.length == gVarArr.length) {
            int i = 0;
            while (true) {
                if (i >= gVarArr2.length) {
                    z = true;
                    break;
                }
                androidx.core.graphics.g gVar = gVarArr2[i];
                char c = gVar.a;
                androidx.core.graphics.g gVar2 = gVarArr[i];
                if (c != gVar2.a || gVar.b.length != gVar2.b.length) {
                    break;
                } else {
                    i++;
                }
            }
        }
        if (!z) {
            this.a = AbstractC3152g6.e(gVarArr);
            return;
        }
        androidx.core.graphics.g[] gVarArr3 = this.a;
        for (int i2 = 0; i2 < gVarArr.length; i2++) {
            gVarArr3[i2].a = gVarArr[i2].a;
            int i3 = 0;
            while (true) {
                float[] fArr = gVarArr[i2].b;
                if (i3 < fArr.length) {
                    gVarArr3[i2].b[i3] = fArr[i3];
                    i3++;
                }
            }
        }
    }

    public l(l lVar) {
        this.a = null;
        this.c = 0;
        this.b = lVar.b;
        this.a = AbstractC3152g6.e(lVar.a);
    }
}
