package androidx.camera.camera2.internal.compat.workaround;

import androidx.camera.camera2.internal.compat.quirk.CaptureIntentPreviewQuirk;
import androidx.camera.camera2.internal.compat.quirk.CrashWhenTakingPhotoWithAutoFlashAEModeQuirk;
import androidx.camera.camera2.internal.compat.quirk.ImageCaptureFailWithAutoFlashQuirk;
import androidx.camera.camera2.internal.compat.quirk.ImageCaptureFailedForVideoSnapshotQuirk;
import androidx.camera.core.impl.e0;
import androidx.camera.core.impl.i0;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class a {
    public boolean a;
    public boolean b;

    public a(boolean z, boolean z2) {
        this.a = z;
        this.b = z2;
    }

    public a(i0 i0Var, int i) {
        boolean z;
        switch (i) {
            case 1:
                i0Var.getClass();
                ArrayList arrayList = new ArrayList();
                Iterator it2 = i0Var.a.iterator();
                while (it2.hasNext()) {
                    e0 e0Var = (e0) it2.next();
                    if (CaptureIntentPreviewQuirk.class.isAssignableFrom(e0Var.getClass())) {
                        arrayList.add(e0Var);
                    }
                }
                Iterator it3 = arrayList.iterator();
                while (true) {
                    if (!it3.hasNext()) {
                        z = false;
                    } else if (((CaptureIntentPreviewQuirk) it3.next()).a()) {
                        z = true;
                    }
                }
                this.a = z;
                this.b = i0Var.a(ImageCaptureFailedForVideoSnapshotQuirk.class);
                break;
            default:
                this.a = i0Var.a(ImageCaptureFailWithAutoFlashQuirk.class);
                this.b = androidx.camera.camera2.internal.compat.quirk.b.a.b(CrashWhenTakingPhotoWithAutoFlashAEModeQuirk.class) != null;
                break;
        }
    }
}
