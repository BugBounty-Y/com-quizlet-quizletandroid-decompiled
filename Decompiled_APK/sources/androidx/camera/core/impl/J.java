package androidx.camera.core.impl;

import android.util.Log;
import android.util.Size;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes.dex */
public abstract class J {
    public static final Size k = new Size(0, 0);
    public static final boolean l = AbstractC3053s1.f(3, "DeferrableSurface");
    public static final AtomicInteger m = new AtomicInteger(0);
    public static final AtomicInteger n = new AtomicInteger(0);
    public final Object a = new Object();
    public int b = 0;
    public boolean c = false;
    public androidx.concurrent.futures.i d;
    public final androidx.concurrent.futures.l e;
    public androidx.concurrent.futures.i f;
    public final androidx.concurrent.futures.l g;
    public final Size h;
    public final int i;
    public Class j;

    public J(Size size, int i) {
        this.h = size;
        this.i = i;
        final int i2 = 0;
        androidx.concurrent.futures.l lVarB = Y5.b(new androidx.concurrent.futures.j(this) { // from class: androidx.camera.core.impl.I
            public final /* synthetic */ J b;

            {
                this.b = this;
            }

            @Override // androidx.concurrent.futures.j
            public final Object d(androidx.concurrent.futures.i iVar) {
                switch (i2) {
                    case 0:
                        J j = this.b;
                        synchronized (j.a) {
                            j.d = iVar;
                        }
                        return "DeferrableSurface-termination(" + j + ")";
                    default:
                        J j2 = this.b;
                        synchronized (j2.a) {
                            j2.f = iVar;
                        }
                        return "DeferrableSurface-close(" + j2 + ")";
                }
            }
        });
        this.e = lVarB;
        final int i3 = 1;
        this.g = Y5.b(new androidx.concurrent.futures.j(this) { // from class: androidx.camera.core.impl.I
            public final /* synthetic */ J b;

            {
                this.b = this;
            }

            @Override // androidx.concurrent.futures.j
            public final Object d(androidx.concurrent.futures.i iVar) {
                switch (i3) {
                    case 0:
                        J j = this.b;
                        synchronized (j.a) {
                            j.d = iVar;
                        }
                        return "DeferrableSurface-termination(" + j + ")";
                    default:
                        J j2 = this.b;
                        synchronized (j2.a) {
                            j2.f = iVar;
                        }
                        return "DeferrableSurface-close(" + j2 + ")";
                }
            }
        });
        if (AbstractC3053s1.f(3, "DeferrableSurface")) {
            n.incrementAndGet();
            m.get();
            e();
            lVarB.b.a(new androidx.activity.r(13, this, Log.getStackTraceString(new Exception())), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
        }
    }

    public void a() {
        androidx.concurrent.futures.i iVar;
        synchronized (this.a) {
            try {
                if (this.c) {
                    iVar = null;
                } else {
                    this.c = true;
                    this.f.b(null);
                    if (this.b == 0) {
                        iVar = this.d;
                        this.d = null;
                    } else {
                        iVar = null;
                    }
                    if (AbstractC3053s1.f(3, "DeferrableSurface")) {
                        toString();
                        AbstractC3053s1.f(3, "DeferrableSurface");
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (iVar != null) {
            iVar.b(null);
        }
    }

    public final void b() {
        androidx.concurrent.futures.i iVar;
        synchronized (this.a) {
            try {
                int i = this.b;
                if (i == 0) {
                    throw new IllegalStateException("Decrementing use count occurs more times than incrementing");
                }
                int i2 = i - 1;
                this.b = i2;
                if (i2 == 0 && this.c) {
                    iVar = this.d;
                    this.d = null;
                } else {
                    iVar = null;
                }
                if (AbstractC3053s1.f(3, "DeferrableSurface")) {
                    toString();
                    AbstractC3053s1.f(3, "DeferrableSurface");
                    if (this.b == 0) {
                        n.get();
                        m.decrementAndGet();
                        e();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (iVar != null) {
            iVar.b(null);
        }
    }

    public final com.google.common.util.concurrent.e c() {
        synchronized (this.a) {
            try {
                if (this.c) {
                    return new androidx.camera.core.impl.utils.futures.k(new DeferrableSurface$SurfaceClosedException("DeferrableSurface already closed.", this), 1);
                }
                return f();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void d() {
        synchronized (this.a) {
            try {
                int i = this.b;
                if (i == 0 && this.c) {
                    throw new DeferrableSurface$SurfaceClosedException("Cannot begin use on a closed surface.", this);
                }
                this.b = i + 1;
                if (AbstractC3053s1.f(3, "DeferrableSurface")) {
                    if (this.b == 1) {
                        n.get();
                        m.incrementAndGet();
                        e();
                    }
                    toString();
                    AbstractC3053s1.f(3, "DeferrableSurface");
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void e() {
        if (!l && AbstractC3053s1.f(3, "DeferrableSurface")) {
            AbstractC3053s1.f(3, "DeferrableSurface");
        }
        toString();
        AbstractC3053s1.f(3, "DeferrableSurface");
    }

    public abstract com.google.common.util.concurrent.e f();
}
