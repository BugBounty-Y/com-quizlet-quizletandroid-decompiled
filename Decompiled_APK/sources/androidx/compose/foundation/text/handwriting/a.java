package androidx.compose.foundation.text.handwriting;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public abstract class a {
    public static final float a = 40;
    public static final float b = 10;

    public static final q a(boolean z, Function0 function0) {
        return (z && e.a) ? AbstractC0382e.v(new StylusHandwritingElementWithNegativePadding(function0), b, a) : n.b;
    }
}
