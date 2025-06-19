package androidx.compose.ui.platform.coreshims;

import android.view.View;
import android.view.contentcapture.ContentCaptureSession;

/* loaded from: classes.dex */
public abstract class f {
    public static ContentCaptureSession a(View view) {
        return view.getContentCaptureSession();
    }
}
