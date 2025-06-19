package androidx.constraintlayout.core;

import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Arrays;

/* loaded from: classes.dex */
public final class g implements Comparable {
    public boolean a;
    public float e;
    public int l;
    public int b = -1;
    public int c = -1;
    public int d = 0;
    public boolean f = false;
    public final float[] g = new float[9];
    public final float[] h = new float[9];
    public b[] i = new b[16];
    public int j = 0;
    public int k = 0;

    public g(int i) {
        this.l = i;
    }

    public final void a(b bVar) {
        int i = 0;
        while (true) {
            int i2 = this.j;
            if (i >= i2) {
                b[] bVarArr = this.i;
                if (i2 >= bVarArr.length) {
                    this.i = (b[]) Arrays.copyOf(bVarArr, bVarArr.length * 2);
                }
                b[] bVarArr2 = this.i;
                int i3 = this.j;
                bVarArr2[i3] = bVar;
                this.j = i3 + 1;
                return;
            }
            if (this.i[i] == bVar) {
                return;
            } else {
                i++;
            }
        }
    }

    public final void b(b bVar) {
        int i = this.j;
        int i2 = 0;
        while (i2 < i) {
            if (this.i[i2] == bVar) {
                while (i2 < i - 1) {
                    b[] bVarArr = this.i;
                    int i3 = i2 + 1;
                    bVarArr[i2] = bVarArr[i3];
                    i2 = i3;
                }
                this.j--;
                return;
            }
            i2++;
        }
    }

    public final void c() {
        this.l = 5;
        this.d = 0;
        this.b = -1;
        this.c = -1;
        this.e = DefinitionKt.NO_Float_VALUE;
        this.f = false;
        int i = this.j;
        for (int i2 = 0; i2 < i; i2++) {
            this.i[i2] = null;
        }
        this.j = 0;
        this.k = 0;
        this.a = false;
        Arrays.fill(this.h, DefinitionKt.NO_Float_VALUE);
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        return this.b - ((g) obj).b;
    }

    public final void d(c cVar, float f) {
        this.e = f;
        this.f = true;
        int i = this.j;
        this.c = -1;
        for (int i2 = 0; i2 < i; i2++) {
            this.i[i2].h(cVar, this, false);
        }
        this.j = 0;
    }

    public final void e(c cVar, b bVar) {
        int i = this.j;
        for (int i2 = 0; i2 < i; i2++) {
            this.i[i2].i(cVar, bVar, false);
        }
        this.j = 0;
    }

    public final String toString() {
        return "" + this.b;
    }
}
