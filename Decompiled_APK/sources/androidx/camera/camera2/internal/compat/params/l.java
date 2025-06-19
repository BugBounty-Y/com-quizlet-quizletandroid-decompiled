package androidx.camera.camera2.internal.compat.params;

import android.hardware.camera2.params.OutputConfiguration;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;

/* loaded from: classes.dex */
public class l extends j {
    @Override // androidx.camera.camera2.internal.compat.params.j
    public Object a() {
        Object obj = this.a;
        AbstractC3242q6.d(obj instanceof k);
        return ((k) obj).a;
    }

    @Override // androidx.camera.camera2.internal.compat.params.j
    public final String b() {
        return null;
    }

    @Override // androidx.camera.camera2.internal.compat.params.j
    public void d(long j) {
        ((k) this.a).b = j;
    }

    @Override // androidx.camera.camera2.internal.compat.params.j
    public final void f(String str) {
        ((OutputConfiguration) a()).setPhysicalCameraId(str);
    }
}
