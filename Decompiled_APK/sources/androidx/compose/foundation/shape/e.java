package androidx.compose.foundation.shape;

import com.quizlet.ui.resources.designsystem.generated.f;

/* loaded from: classes.dex */
public abstract class e {
    public static final d a;

    static {
        c cVar = new c(50);
        a = new d(cVar, cVar, cVar, cVar);
    }

    public static final d a(float f) {
        b bVar = new b(f);
        return new d(bVar, bVar, bVar, bVar);
    }

    public static d b(float f, float f2, int i) {
        float f3 = f.j;
        if ((i & 1) != 0) {
            f = 0;
        }
        if ((i & 2) != 0) {
            f2 = 0;
        }
        float f4 = (i & 4) != 0 ? 0 : f3;
        if ((i & 8) != 0) {
            f3 = 0;
        }
        return new d(new b(f), new b(f2), new b(f4), new b(f3));
    }
}
