package kotlinx.coroutines.android;

import android.os.Handler;
import android.os.Looper;
import com.quizlet.quizletandroid.ui.subject.f;
import java.util.concurrent.CancellationException;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.E;
import kotlinx.coroutines.J;
import kotlinx.coroutines.O;
import kotlinx.coroutines.Q;
import kotlinx.coroutines.internal.m;
import kotlinx.coroutines.v0;

/* loaded from: classes3.dex */
public final class d extends AbstractC5040y implements J {
    public final Handler b;
    public final String c;
    public final boolean d;
    public final d e;

    public d(Handler handler, String str, boolean z) {
        this.b = handler;
        this.c = str;
        this.d = z;
        this.e = z ? this : new d(handler, str, true);
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final boolean a0(CoroutineContext coroutineContext) {
        return (this.d && Intrinsics.b(Looper.myLooper(), this.b.getLooper())) ? false : true;
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public AbstractC5040y c0(int i) {
        kotlinx.coroutines.internal.b.a(i);
        return this;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return dVar.b == this.b && dVar.d == this.d;
    }

    @Override // kotlinx.coroutines.J
    public final void f(long j, C5028l c5028l) {
        com.skydoves.balloon.compose.a aVar = new com.skydoves.balloon.compose.a(6, c5028l, this);
        if (j > 4611686018427387903L) {
            j = 4611686018427387903L;
        }
        if (this.b.postDelayed(aVar, j)) {
            c5028l.u(new f(10, this, aVar));
        } else {
            k0(c5028l.e, aVar);
        }
    }

    public final int hashCode() {
        return System.identityHashCode(this.b) ^ (this.d ? 1231 : 1237);
    }

    @Override // kotlinx.coroutines.J
    public final Q i(long j, final Runnable runnable, CoroutineContext coroutineContext) {
        if (j > 4611686018427387903L) {
            j = 4611686018427387903L;
        }
        if (this.b.postDelayed(runnable, j)) {
            return new Q() { // from class: kotlinx.coroutines.android.c
                @Override // kotlinx.coroutines.Q
                public final void dispose() {
                    this.a.b.removeCallbacks(runnable);
                }
            };
        }
        k0(coroutineContext, runnable);
        return v0.a;
    }

    public final void k0(CoroutineContext coroutineContext, Runnable runnable) {
        E.h(coroutineContext, new CancellationException("The task was rejected, the handler underlying the dispatcher '" + this + "' was closed"));
        kotlinx.coroutines.scheduling.e eVar = O.a;
        kotlinx.coroutines.scheduling.d.b.r(coroutineContext, runnable);
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final void r(CoroutineContext coroutineContext, Runnable runnable) {
        if (this.b.post(runnable)) {
            return;
        }
        k0(coroutineContext, runnable);
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final String toString() {
        d dVar;
        String str;
        kotlinx.coroutines.scheduling.e eVar = O.a;
        d dVar2 = m.a;
        if (this == dVar2) {
            str = "Dispatchers.Main";
        } else {
            try {
                dVar = dVar2.e;
            } catch (UnsupportedOperationException unused) {
                dVar = null;
            }
            str = this == dVar ? "Dispatchers.Main.immediate" : null;
        }
        if (str != null) {
            return str;
        }
        String string = this.c;
        if (string == null) {
            string = this.b.toString();
        }
        return this.d ? android.support.v4.media.session.a.k(string, ".immediate") : string;
    }

    public d(Handler handler) {
        this(handler, null, false);
    }
}
