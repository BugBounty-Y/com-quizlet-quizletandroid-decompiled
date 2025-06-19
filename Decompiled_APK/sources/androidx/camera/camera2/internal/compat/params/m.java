package androidx.camera.camera2.internal.compat.params;

import android.hardware.camera2.params.OutputConfiguration;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;

/* loaded from: classes.dex */
public final class m extends l {
    @Override // androidx.camera.camera2.internal.compat.params.l, androidx.camera.camera2.internal.compat.params.j
    public final Object a() {
        Object obj = this.a;
        AbstractC3242q6.d(obj instanceof OutputConfiguration);
        return obj;
    }

    @Override // androidx.camera.camera2.internal.compat.params.l, androidx.camera.camera2.internal.compat.params.j
    public final void d(long j) {
        ((OutputConfiguration) a()).setDynamicRangeProfile(j);
    }

    @Override // androidx.camera.camera2.internal.compat.params.j
    public final void e(int i) {
        ((OutputConfiguration) a()).setMirrorMode(i);
    }

    @Override // androidx.camera.camera2.internal.compat.params.j
    public final void g(long j) {
        if (j == -1) {
            return;
        }
        ((OutputConfiguration) a()).setStreamUseCase(j);
    }
}
