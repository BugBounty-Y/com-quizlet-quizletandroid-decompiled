package androidx.camera.camera2.internal.compat.params;

import android.hardware.camera2.params.DynamicRangeProfiles;
import androidx.camera.core.C0196t;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import java.util.Collections;
import java.util.Set;

/* loaded from: classes.dex */
public final class d implements b {
    public static final com.google.firebase.platforminfo.c a = new com.google.firebase.platforminfo.c(new d());
    public static final Set b = Collections.singleton(C0196t.d);

    @Override // androidx.camera.camera2.internal.compat.params.b
    public final DynamicRangeProfiles a() {
        return null;
    }

    @Override // androidx.camera.camera2.internal.compat.params.b
    public final Set b() {
        return b;
    }

    @Override // androidx.camera.camera2.internal.compat.params.b
    public final Set c(C0196t c0196t) {
        AbstractC3242q6.c("DynamicRange is not supported: " + c0196t, C0196t.d.equals(c0196t));
        return b;
    }
}
