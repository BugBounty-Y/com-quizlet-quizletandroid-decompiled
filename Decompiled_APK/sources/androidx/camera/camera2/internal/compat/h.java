package androidx.camera.camera2.internal.compat;

import android.os.Handler;
import android.os.Looper;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3224o6;

/* loaded from: classes.dex */
public final class h {
    public final Handler a;

    public h() {
        this.a = AbstractC3224o6.b(Looper.getMainLooper());
    }

    public h(Handler handler) {
        this.a = handler;
    }
}
