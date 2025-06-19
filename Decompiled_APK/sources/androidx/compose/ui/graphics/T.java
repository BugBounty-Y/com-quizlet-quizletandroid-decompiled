package androidx.compose.ui.graphics;

import android.graphics.Paint;
import android.graphics.Shader;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class T extends AbstractC0857q {
    public Shader a;
    public long b = 9205357640488583168L;

    @Override // androidx.compose.ui.graphics.AbstractC0857q
    public final void a(float f, long j, com.google.android.gms.cloudmessaging.k kVar) {
        Shader shaderB = this.a;
        if (shaderB == null || !androidx.compose.ui.geometry.e.a(this.b, j)) {
            if (androidx.compose.ui.geometry.e.e(j)) {
                shaderB = null;
                this.a = null;
                this.b = 9205357640488583168L;
            } else {
                shaderB = b(j);
                this.a = shaderB;
                this.b = j;
            }
        }
        long jC = F.c(((Paint) kVar.c).getColor());
        long j2 = C0861v.b;
        if (!C0861v.c(jC, j2)) {
            kVar.f(j2);
        }
        if (!Intrinsics.b((Shader) kVar.d, shaderB)) {
            kVar.i(shaderB);
        }
        if (((Paint) kVar.c).getAlpha() / 255.0f == f) {
            return;
        }
        kVar.d(f);
    }

    public abstract Shader b(long j);
}
