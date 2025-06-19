package androidx.glance.session;

import androidx.camera.camera2.internal.s0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3397u1;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class K implements kotlinx.coroutines.C {
    public final /* synthetic */ kotlinx.coroutines.C a;
    public final AtomicReference b = new AtomicReference(null);
    public final /* synthetic */ s0 c;
    public final /* synthetic */ kotlinx.coroutines.C d;
    public final /* synthetic */ x e;
    public final /* synthetic */ AtomicReference f;

    public K(kotlinx.coroutines.C c, s0 s0Var, kotlinx.coroutines.C c2, x xVar, AtomicReference atomicReference) {
        this.c = s0Var;
        this.d = c2;
        this.e = xVar;
        this.f = atomicReference;
        this.a = c;
    }

    public final long a() {
        Long l = (Long) this.b.get();
        if (l == null) {
            kotlin.time.b.b.getClass();
            return kotlin.time.b.c;
        }
        long jLongValue = l.longValue();
        this.c.getClass();
        long jCurrentTimeMillis = jLongValue - System.currentTimeMillis();
        kotlin.time.a aVar = kotlin.time.b.b;
        return AbstractC3397u1.g(jCurrentTimeMillis, kotlin.time.d.c);
    }

    public final void b(long j) {
        if (kotlin.time.b.e(j) <= 0) {
            kotlinx.coroutines.E.i(this.d, new TimeoutCancellationException("Timed out immediately", this.e.hashCode()));
            return;
        }
        if (kotlin.time.b.c(a(), j) < 0) {
            return;
        }
        AtomicReference atomicReference = this.b;
        this.c.getClass();
        atomicReference.set(Long.valueOf(kotlin.time.b.e(j) + System.currentTimeMillis()));
        s0 s0Var = this.c;
        kotlinx.coroutines.C c = this.d;
        InterfaceC5025j0 interfaceC5025j0 = (InterfaceC5025j0) this.f.getAndSet(kotlinx.coroutines.E.A(c, null, null, new J(this, s0Var, c, this.e, null), 3));
        if (interfaceC5025j0 != null) {
            interfaceC5025j0.j(null);
        }
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return this.a.getCoroutineContext();
    }
}
