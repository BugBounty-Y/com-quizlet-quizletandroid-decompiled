package androidx.camera.core;

import android.media.ImageReader;
import android.util.LongSparseArray;
import android.view.Surface;
import androidx.camera.camera2.internal.C0132i;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final class T implements androidx.camera.core.impl.S, InterfaceC0198v {
    public final Object a;
    public final S b;
    public int c;
    public final C0132i d;
    public boolean e;
    public final com.bumptech.glide.manager.p f;
    public androidx.camera.core.impl.Q g;
    public Executor h;
    public final LongSparseArray i;
    public final LongSparseArray j;
    public int k;
    public final ArrayList l;
    public final ArrayList m;

    public T(int i, int i2, int i3, int i4) {
        com.bumptech.glide.manager.p pVar = new com.bumptech.glide.manager.p(ImageReader.newInstance(i, i2, i3, i4));
        this.a = new Object();
        this.b = new S(this, 0);
        this.c = 0;
        this.d = new C0132i(this, 5);
        this.e = false;
        this.i = new LongSparseArray();
        this.j = new LongSparseArray();
        this.m = new ArrayList();
        this.f = pVar;
        this.k = 0;
        this.l = new ArrayList(C());
    }

    @Override // androidx.camera.core.impl.S
    public final int C() {
        int iC;
        synchronized (this.a) {
            iC = this.f.C();
        }
        return iC;
    }

    @Override // androidx.camera.core.impl.S
    public final O F() {
        synchronized (this.a) {
            try {
                if (this.l.isEmpty()) {
                    return null;
                }
                if (this.k >= this.l.size()) {
                    throw new IllegalStateException("Maximum image number reached.");
                }
                ArrayList arrayList = this.l;
                int i = this.k;
                this.k = i + 1;
                O o = (O) arrayList.get(i);
                this.m.add(o);
                return o;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // androidx.camera.core.impl.S
    public final void G(androidx.camera.core.impl.Q q, Executor executor) {
        synchronized (this.a) {
            q.getClass();
            this.g = q;
            executor.getClass();
            this.h = executor;
            this.f.G(this.d, executor);
        }
    }

    @Override // androidx.camera.core.InterfaceC0198v
    public final void a(AbstractC0199w abstractC0199w) {
        synchronized (this.a) {
            c(abstractC0199w);
        }
    }

    @Override // androidx.camera.core.impl.S
    public final int b() {
        int iB;
        synchronized (this.a) {
            iB = this.f.b();
        }
        return iB;
    }

    public final void c(AbstractC0199w abstractC0199w) {
        synchronized (this.a) {
            try {
                int iIndexOf = this.l.indexOf(abstractC0199w);
                if (iIndexOf >= 0) {
                    this.l.remove(iIndexOf);
                    int i = this.k;
                    if (iIndexOf <= i) {
                        this.k = i - 1;
                    }
                }
                this.m.remove(abstractC0199w);
                if (this.c > 0) {
                    e(this.f);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // androidx.camera.core.impl.S
    public final void close() {
        synchronized (this.a) {
            try {
                if (this.e) {
                    return;
                }
                Iterator it2 = new ArrayList(this.l).iterator();
                while (it2.hasNext()) {
                    ((O) it2.next()).close();
                }
                this.l.clear();
                this.f.close();
                this.e = true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void d(b0 b0Var) {
        androidx.camera.core.impl.Q q;
        Executor executor;
        synchronized (this.a) {
            try {
                if (this.l.size() < C()) {
                    b0Var.a(this);
                    this.l.add(b0Var);
                    q = this.g;
                    executor = this.h;
                } else {
                    AbstractC3053s1.f(3, "TAG");
                    b0Var.close();
                    q = null;
                    executor = null;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (q != null) {
            if (executor != null) {
                executor.execute(new androidx.activity.r(11, this, q));
            } else {
                q.e(this);
            }
        }
    }

    public final void e(androidx.camera.core.impl.S s) {
        O oF;
        synchronized (this.a) {
            try {
                if (this.e) {
                    return;
                }
                int size = this.j.size() + this.l.size();
                if (size >= s.C()) {
                    AbstractC3053s1.f(3, "MetadataImageReader");
                    return;
                }
                do {
                    try {
                        oF = s.F();
                        if (oF != null) {
                            this.c--;
                            size++;
                            this.j.put(oF.N().a(), oF);
                            f();
                        }
                    } catch (IllegalStateException unused) {
                        AbstractC3053s1.f(3, "MetadataImageReader");
                        oF = null;
                    }
                    if (oF == null || this.c <= 0) {
                        break;
                    }
                } while (size < s.C());
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void f() {
        synchronized (this.a) {
            try {
                for (int size = this.i.size() - 1; size >= 0; size--) {
                    M m = (M) this.i.valueAt(size);
                    long jA = m.a();
                    O o = (O) this.j.get(jA);
                    if (o != null) {
                        this.j.remove(jA);
                        this.i.removeAt(size);
                        d(new b0(o, null, m));
                    }
                }
                g();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void g() {
        synchronized (this.a) {
            try {
                if (this.j.size() != 0 && this.i.size() != 0) {
                    long jKeyAt = this.j.keyAt(0);
                    Long lValueOf = Long.valueOf(jKeyAt);
                    long jKeyAt2 = this.i.keyAt(0);
                    AbstractC3242q6.d(!Long.valueOf(jKeyAt2).equals(lValueOf));
                    if (jKeyAt2 > jKeyAt) {
                        for (int size = this.j.size() - 1; size >= 0; size--) {
                            if (this.j.keyAt(size) < jKeyAt2) {
                                ((O) this.j.valueAt(size)).close();
                                this.j.removeAt(size);
                            }
                        }
                    } else {
                        for (int size2 = this.i.size() - 1; size2 >= 0; size2--) {
                            if (this.i.keyAt(size2) < jKeyAt) {
                                this.i.removeAt(size2);
                            }
                        }
                    }
                }
            } finally {
            }
        }
    }

    @Override // androidx.camera.core.impl.S
    public final int getWidth() {
        int width;
        synchronized (this.a) {
            width = this.f.getWidth();
        }
        return width;
    }

    @Override // androidx.camera.core.impl.S
    public final O l() {
        synchronized (this.a) {
            try {
                if (this.l.isEmpty()) {
                    return null;
                }
                if (this.k >= this.l.size()) {
                    throw new IllegalStateException("Maximum image number reached.");
                }
                ArrayList arrayList = new ArrayList();
                for (int i = 0; i < this.l.size() - 1; i++) {
                    if (!this.m.contains(this.l.get(i))) {
                        arrayList.add((O) this.l.get(i));
                    }
                }
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    ((O) it2.next()).close();
                }
                int size = this.l.size();
                ArrayList arrayList2 = this.l;
                this.k = size;
                O o = (O) arrayList2.get(size - 1);
                this.m.add(o);
                return o;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // androidx.camera.core.impl.S
    public final int m() {
        int iM;
        synchronized (this.a) {
            iM = this.f.m();
        }
        return iM;
    }

    @Override // androidx.camera.core.impl.S
    public final void p() {
        synchronized (this.a) {
            this.f.p();
            this.g = null;
            this.h = null;
            this.c = 0;
        }
    }

    @Override // androidx.camera.core.impl.S
    public final Surface w() {
        Surface surfaceW;
        synchronized (this.a) {
            surfaceW = this.f.w();
        }
        return surfaceW;
    }
}
