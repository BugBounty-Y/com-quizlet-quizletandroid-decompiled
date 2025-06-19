package io.reactivex.rxjava3.internal.schedulers;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;

/* loaded from: classes3.dex */
public abstract class t {
    public static final boolean a;

    static {
        boolean zEquals = true;
        try {
            String property = System.getProperty("rx3.purge-enabled");
            if (property != null) {
                zEquals = "true".equals(property);
            }
        } catch (Throwable th) {
            x7.b(th);
        }
        a = zEquals;
    }
}
