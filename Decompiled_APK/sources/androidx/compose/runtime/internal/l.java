package androidx.compose.runtime.internal;

import android.os.Looper;

/* loaded from: classes.dex */
public abstract class l {
    public static final long a;

    static {
        long id;
        try {
            id = Looper.getMainLooper().getThread().getId();
        } catch (Exception unused) {
            id = -1;
        }
        a = id;
    }
}
