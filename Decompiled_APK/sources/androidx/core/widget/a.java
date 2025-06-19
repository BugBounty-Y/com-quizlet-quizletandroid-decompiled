package androidx.core.widget;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class a {
    public int a;
    public int b;
    public float c;
    public float d;
    public long e;
    public long f;
    public long g;
    public float h;
    public int i;

    public final float a(long j) {
        if (j < this.e) {
            return DefinitionKt.NO_Float_VALUE;
        }
        long j2 = this.g;
        if (j2 < 0 || j < j2) {
            return f.b((j - r0) / this.a, DefinitionKt.NO_Float_VALUE, 1.0f) * 0.5f;
        }
        float f = this.h;
        return (f.b((j - j2) / this.i, DefinitionKt.NO_Float_VALUE, 1.0f) * f) + (1.0f - f);
    }
}
