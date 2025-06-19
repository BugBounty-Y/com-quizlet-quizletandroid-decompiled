package androidx.camera.camera2.internal;

import android.hardware.camera2.params.MeteringRectangle;

/* loaded from: classes.dex */
public final class X {
    public static final MeteringRectangle[] h = new MeteringRectangle[0];
    public final C0137n a;
    public volatile boolean b = false;
    public int c = 1;
    public MeteringRectangle[] d;
    public MeteringRectangle[] e;
    public MeteringRectangle[] f;
    public final boolean g;

    public X(C0137n c0137n, androidx.camera.core.impl.utils.executor.e eVar, androidx.camera.core.impl.utils.executor.k kVar) {
        MeteringRectangle[] meteringRectangleArr = h;
        this.d = meteringRectangleArr;
        this.e = meteringRectangleArr;
        this.f = meteringRectangleArr;
        this.g = false;
        this.a = c0137n;
    }
}
