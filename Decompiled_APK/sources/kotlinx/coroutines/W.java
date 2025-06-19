package kotlinx.coroutines;

import com.android.billingclient.api.C1472a;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.Unit;

/* loaded from: classes3.dex */
public abstract class W implements Runnable, Comparable, Q {
    private volatile Object _heap;
    public long a;
    public int b = -1;

    public W(long j) {
        this.a = j;
    }

    public final int a(long j, X x, Y y) {
        synchronized (this) {
            if (this._heap == E.b) {
                return 2;
            }
            synchronized (x) {
                try {
                    W[] wArr = x.a;
                    W w = wArr != null ? wArr[0] : null;
                    AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = Y.f;
                    y.getClass();
                    if (Y.h.get(y) == 1) {
                        return 1;
                    }
                    if (w == null) {
                        x.c = j;
                    } else {
                        long j2 = w.a;
                        if (j2 - j < 0) {
                            j = j2;
                        }
                        if (j - x.c > 0) {
                            x.c = j;
                        }
                    }
                    long j3 = this.a;
                    long j4 = x.c;
                    if (j3 - j4 < 0) {
                        this.a = j4;
                    }
                    x.a(this);
                    return 0;
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    public final void b(X x) {
        if (this._heap == E.b) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        this._heap = x;
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        long j = this.a - ((W) obj).a;
        if (j > 0) {
            return 1;
        }
        return j < 0 ? -1 : 0;
    }

    @Override // kotlinx.coroutines.Q
    public final void dispose() {
        synchronized (this) {
            try {
                Object obj = this._heap;
                C1472a c1472a = E.b;
                if (obj == c1472a) {
                    return;
                }
                X x = obj instanceof X ? (X) obj : null;
                if (x != null) {
                    synchronized (x) {
                        Object obj2 = this._heap;
                        if ((obj2 instanceof kotlinx.coroutines.internal.u ? (kotlinx.coroutines.internal.u) obj2 : null) != null) {
                            x.b(this.b);
                        }
                    }
                }
                this._heap = c1472a;
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public String toString() {
        return androidx.compose.animation.d0.q(new StringBuilder("Delayed[nanos="), this.a, ']');
    }
}
