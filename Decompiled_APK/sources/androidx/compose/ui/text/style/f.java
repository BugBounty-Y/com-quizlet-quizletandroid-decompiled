package androidx.compose.ui.text.style;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public abstract class f {
    public static final float a;
    public static final float b;
    public static final float c;

    static {
        a(DefinitionKt.NO_Float_VALUE);
        a(0.5f);
        a = 0.5f;
        a(-1.0f);
        b = -1.0f;
        a(1.0f);
        c = 1.0f;
    }

    public static void a(float f) {
        if ((DefinitionKt.NO_Float_VALUE > f || f > 1.0f) && f != -1.0f) {
            throw new IllegalStateException("topRatio should be in [0..1] range or -1");
        }
    }
}
