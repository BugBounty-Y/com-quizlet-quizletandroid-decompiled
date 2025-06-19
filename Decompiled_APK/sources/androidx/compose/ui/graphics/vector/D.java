package androidx.compose.ui.graphics.vector;

import androidx.compose.runtime.C0775b0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public abstract class D {
    public C0775b0 a;

    public abstract void a(androidx.compose.ui.graphics.drawscope.d dVar);

    public Function1 b() {
        return this.a;
    }

    public final void c() {
        Function1 function1B = b();
        if (function1B != null) {
            function1B.invoke(this);
        }
    }

    public void d(C0775b0 c0775b0) {
        this.a = c0775b0;
    }
}
