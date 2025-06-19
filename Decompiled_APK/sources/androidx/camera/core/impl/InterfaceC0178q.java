package androidx.camera.core.impl;

/* renamed from: androidx.camera.core.impl.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public interface InterfaceC0178q extends j0 {
    public static final C0162c R = new C0162c("camerax.core.camera.useCaseConfigFactory", D0.class, null);
    public static final C0162c S = new C0162c("camerax.core.camera.useCaseCombinationRequiredRule", Integer.class, null);
    public static final C0162c T = new C0162c("camerax.core.camera.SessionProcessor", r0.class, null);
    public static final C0162c U = new C0162c("camerax.core.camera.isPostviewSupported", Boolean.class, null);
    public static final C0162c a0 = new C0162c("camerax.core.camera.isCaptureProcessProgressSupported", Boolean.class, null);

    default void y() {
        if (j(T, null) != null) {
            throw new ClassCastException();
        }
    }
}
