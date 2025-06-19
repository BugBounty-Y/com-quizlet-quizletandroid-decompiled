package androidx.camera.core.impl;

import androidx.camera.core.C0196t;

/* loaded from: classes.dex */
public interface O extends j0 {
    public static final C0162c b0 = new C0162c("camerax.core.imageInput.inputFormat", Integer.TYPE, null);
    public static final C0162c c0 = new C0162c("camerax.core.imageInput.inputDynamicRange", C0196t.class, null);

    default int o() {
        return ((Integer) e(b0)).intValue();
    }
}
