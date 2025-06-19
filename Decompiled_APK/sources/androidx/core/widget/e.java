package androidx.core.widget;

import android.content.Context;
import android.os.Build;
import android.widget.EdgeEffect;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class e {
    @Deprecated
    public e(Context context) {
        new EdgeEffect(context);
    }

    public static float a(EdgeEffect edgeEffect) {
        return Build.VERSION.SDK_INT >= 31 ? d.b(edgeEffect) : DefinitionKt.NO_Float_VALUE;
    }

    public static float b(EdgeEffect edgeEffect, float f, float f2) {
        if (Build.VERSION.SDK_INT >= 31) {
            return d.c(edgeEffect, f, f2);
        }
        c.a(edgeEffect, f, f2);
        return f;
    }
}
