package androidx.compose.ui.text.font;

import androidx.compose.foundation.text.selection.n0;
import androidx.compose.runtime.C0775b0;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class k implements i {
    public final C0987a a;
    public final C0988b b;
    public final com.quizlet.data.repository.activitycenter.b c;
    public final p d;
    public final com.google.android.gms.internal.instantapps.a e;
    public final C0775b0 f;

    public k(C0987a c0987a, C0988b c0988b) {
        com.quizlet.data.repository.activitycenter.b bVar = l.a;
        p pVar = new p(l.b);
        com.google.android.gms.internal.instantapps.a aVar = new com.google.android.gms.internal.instantapps.a(11);
        this.a = c0987a;
        this.b = c0988b;
        this.c = bVar;
        this.d = pVar;
        this.e = aVar;
        this.f = new C0775b0(this, 25);
    }

    public final H a(E e) {
        com.quizlet.data.repository.activitycenter.b bVar = this.c;
        n0 n0Var = new n0(26, this, e);
        synchronized (((com.google.android.gms.internal.mlkit_common.u) bVar.b)) {
            H h = (H) ((androidx.compose.ui.text.caches.b) bVar.c).b(e);
            if (h != null) {
                if (h.c()) {
                    return h;
                }
            }
            try {
                H h2 = (H) n0Var.invoke(new n0(27, bVar, e));
                synchronized (((com.google.android.gms.internal.mlkit_common.u) bVar.b)) {
                    try {
                        if (((androidx.compose.ui.text.caches.b) bVar.c).b(e) == null && h2.c()) {
                            ((androidx.compose.ui.text.caches.b) bVar.c).e(e, h2);
                        }
                        Unit unit = Unit.a;
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return h2;
            } catch (Exception e2) {
                throw new IllegalStateException("Could not load font", e2);
            }
        }
    }

    public final H b(j jVar, u uVar, int i, int i2) {
        C0988b c0988b = this.b;
        c0988b.getClass();
        int i3 = c0988b.a;
        u uVar2 = (i3 == 0 || i3 == Integer.MAX_VALUE) ? uVar : new u(kotlin.ranges.l.c(uVar.a + i3, 1, 1000));
        this.a.getClass();
        return a(new E(jVar, uVar2, i, i2, null));
    }
}
