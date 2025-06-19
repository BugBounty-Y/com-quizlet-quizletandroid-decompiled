package androidx.camera.camera2.internal.compat;

import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.util.ArrayMap;
import androidx.compose.foundation.text.input.internal.u;

/* loaded from: classes.dex */
public final class q {
    public final u a;
    public final ArrayMap b = new ArrayMap(4);

    public q(u uVar) {
        this.a = uVar;
    }

    public static q a(Context context, Handler handler) {
        int i = Build.VERSION.SDK_INT;
        return new q(i >= 30 ? new t(context, null) : i >= 29 ? new s(context, null) : i >= 28 ? new r(context, null) : new u(context, new com.quizlet.data.repository.widget.b(handler)));
    }

    public final k b(String str) {
        k kVar;
        synchronized (this.b) {
            kVar = (k) this.b.get(str);
            if (kVar == null) {
                try {
                    k kVar2 = new k(this.a.f(str), str);
                    this.b.put(str, kVar2);
                    kVar = kVar2;
                } catch (AssertionError e) {
                    throw new CameraAccessExceptionCompat(e.getMessage(), e);
                }
            }
        }
        return kVar;
    }
}
