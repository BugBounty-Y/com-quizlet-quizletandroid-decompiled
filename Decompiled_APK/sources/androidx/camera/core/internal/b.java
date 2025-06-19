package androidx.camera.core.internal;

/* loaded from: classes.dex */
public final class b {
    public final float a;
    public final float b;
    public final float c;
    public final float d;

    public b(float f, float f2, float f3, float f4) {
        this.a = f;
        this.b = f2;
        this.c = f3;
        this.d = f4;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof b) {
            b bVar = (b) obj;
            if (Float.floatToIntBits(this.a) == Float.floatToIntBits(bVar.a) && Float.floatToIntBits(this.b) == Float.floatToIntBits(bVar.b) && Float.floatToIntBits(this.c) == Float.floatToIntBits(bVar.c) && Float.floatToIntBits(this.d) == Float.floatToIntBits(bVar.d)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((((((Float.floatToIntBits(this.a) ^ 1000003) * 1000003) ^ Float.floatToIntBits(this.b)) * 1000003) ^ Float.floatToIntBits(this.c)) * 1000003) ^ Float.floatToIntBits(this.d);
    }

    public final String toString() {
        return "ImmutableZoomState{zoomRatio=" + this.a + ", maxZoomRatio=" + this.b + ", minZoomRatio=" + this.c + ", linearZoom=" + this.d + "}";
    }
}
