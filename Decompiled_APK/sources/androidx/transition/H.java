package androidx.transition;

import android.os.Build;

/* loaded from: classes.dex */
public abstract class H {
    public static final boolean a;

    static {
        a = Build.VERSION.SDK_INT >= 28;
    }
}
