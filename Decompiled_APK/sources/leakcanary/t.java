package leakcanary;

import android.app.Application;
import android.os.Build;
import android.os.Handler;

/* loaded from: classes3.dex */
public final class t extends w {
    public t() {
        super("TEXT_LINE_POOL", 1);
    }

    @Override // leakcanary.w
    public final void a(Application application) {
        if (Build.VERSION.SDK_INT >= 28) {
            return;
        }
        ((Handler) w.c.getValue()).post(new com.google.android.gms.common.api.internal.w(this, application));
    }
}
