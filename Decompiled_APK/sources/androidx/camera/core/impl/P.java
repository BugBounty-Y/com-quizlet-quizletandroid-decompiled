package androidx.camera.core.impl;

import android.util.Size;
import androidx.camera.core.AbstractC0151c;
import java.util.List;

/* loaded from: classes.dex */
public interface P extends j0 {
    public static final C0162c d0 = new C0162c("camerax.core.imageOutput.targetAspectRatio", AbstractC0151c.class, null);
    public static final C0162c e0;
    public static final C0162c f0;
    public static final C0162c g0;
    public static final C0162c h0;
    public static final C0162c i0;
    public static final C0162c j0;
    public static final C0162c k0;
    public static final C0162c l0;
    public static final C0162c m0;

    static {
        Class cls = Integer.TYPE;
        e0 = new C0162c("camerax.core.imageOutput.targetRotation", cls, null);
        f0 = new C0162c("camerax.core.imageOutput.appTargetRotation", cls, null);
        g0 = new C0162c("camerax.core.imageOutput.mirrorMode", cls, null);
        h0 = new C0162c("camerax.core.imageOutput.targetResolution", Size.class, null);
        i0 = new C0162c("camerax.core.imageOutput.defaultResolution", Size.class, null);
        j0 = new C0162c("camerax.core.imageOutput.maxResolution", Size.class, null);
        k0 = new C0162c("camerax.core.imageOutput.supportedResolutions", List.class, null);
        l0 = new C0162c("camerax.core.imageOutput.resolutionSelector", androidx.camera.core.resolutionselector.b.class, null);
        m0 = new C0162c("camerax.core.imageOutput.customOrderedResolutions", List.class, null);
    }

    static void u(P p) {
        boolean zC = p.c(d0);
        boolean z = ((Size) p.j(h0, null)) != null;
        if (zC && z) {
            throw new IllegalArgumentException("Cannot use both setTargetResolution and setTargetAspectRatio on the same config.");
        }
        if (((androidx.camera.core.resolutionselector.b) p.j(l0, null)) != null) {
            if (zC || z) {
                throw new IllegalArgumentException("Cannot use setTargetResolution or setTargetAspectRatio with setResolutionSelector on the same config.");
            }
        }
    }

    default int v() {
        return ((Integer) j(e0, 0)).intValue();
    }
}
