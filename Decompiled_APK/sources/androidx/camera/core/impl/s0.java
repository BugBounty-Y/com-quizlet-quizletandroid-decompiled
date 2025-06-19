package androidx.camera.core.impl;

import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes.dex */
public final class s0 implements Runnable {
    public static final Object h = new Object();
    public final Executor a;
    public final InterfaceC0159a0 b;
    public final AtomicReference d;
    public final AtomicBoolean c = new AtomicBoolean(true);
    public Object e = h;
    public int f = -1;
    public boolean g = false;

    public s0(AtomicReference atomicReference, Executor executor, InterfaceC0159a0 interfaceC0159a0) {
        this.d = atomicReference;
        this.a = executor;
        this.b = interfaceC0159a0;
    }

    public final void a(int i) {
        synchronized (this) {
            try {
                if (this.c.get()) {
                    if (i <= this.f) {
                        return;
                    }
                    this.f = i;
                    if (this.g) {
                        return;
                    }
                    this.g = true;
                    try {
                        this.a.execute(this);
                    } catch (Throwable unused) {
                        synchronized (this) {
                            this.g = false;
                        }
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // java.lang.Runnable
    public final void run() {
        synchronized (this) {
            try {
                if (!this.c.get()) {
                    this.g = false;
                    return;
                }
                Object obj = this.d.get();
                int i = this.f;
                while (true) {
                    if (!Objects.equals(this.e, obj)) {
                        this.e = obj;
                        if (obj instanceof AbstractC0167f) {
                            InterfaceC0159a0 interfaceC0159a0 = this.b;
                            ((AbstractC0167f) obj).getClass();
                            interfaceC0159a0.onError(null);
                        } else {
                            this.b.k(obj);
                        }
                    }
                    synchronized (this) {
                        try {
                            if (i == this.f || !this.c.get()) {
                                break;
                            }
                            obj = this.d.get();
                            i = this.f;
                        } finally {
                        }
                    }
                }
                this.g = false;
            } finally {
            }
        }
    }
}
