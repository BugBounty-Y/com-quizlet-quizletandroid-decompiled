package androidx.camera.core;

import android.util.Size;

/* loaded from: classes.dex */
public final class b0 extends AbstractC0199w {
    public final Object d;
    public final M e;
    public final int f;
    public final int g;

    public b0(O o, Size size, M m) {
        super(o);
        this.d = new Object();
        if (size == null) {
            this.f = this.b.getWidth();
            this.g = this.b.b();
        } else {
            this.f = size.getWidth();
            this.g = size.getHeight();
        }
        this.e = m;
    }

    @Override // androidx.camera.core.AbstractC0199w, androidx.camera.core.O
    public final M N() {
        return this.e;
    }

    @Override // androidx.camera.core.AbstractC0199w, androidx.camera.core.O
    public final int b() {
        return this.g;
    }

    @Override // androidx.camera.core.AbstractC0199w, androidx.camera.core.O
    public final int getWidth() {
        return this.f;
    }
}
