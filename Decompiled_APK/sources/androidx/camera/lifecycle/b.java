package androidx.camera.lifecycle;

import androidx.annotation.NonNull;
import androidx.camera.core.InterfaceC0188k;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.lifecycle.A;
import androidx.lifecycle.B;
import androidx.lifecycle.I;
import androidx.lifecycle.InterfaceC1238a0;
import androidx.lifecycle.J;
import androidx.lifecycle.L;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* loaded from: classes.dex */
public final class b implements I, InterfaceC0188k {
    public final J b;
    public final androidx.camera.core.internal.g c;
    public final Object a = new Object();
    public boolean d = false;

    public b(J j, androidx.camera.core.internal.g gVar) {
        this.b = j;
        this.c = gVar;
        if (((L) j.getLifecycle()).d.a(B.d)) {
            gVar.d();
        } else {
            gVar.s();
        }
        j.getLifecycle().a(this);
    }

    @Override // androidx.camera.core.InterfaceC0188k
    public final InterfaceC0183w a() {
        return this.c.p;
    }

    public final List c() {
        List listUnmodifiableList;
        synchronized (this.a) {
            listUnmodifiableList = Collections.unmodifiableList(this.c.w());
        }
        return listUnmodifiableList;
    }

    public final void e() {
        synchronized (this.a) {
            try {
                if (this.d) {
                    return;
                }
                onStop(this.b);
                this.d = true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void o() {
        synchronized (this.a) {
            try {
                if (this.d) {
                    this.d = false;
                    if (((L) this.b.getLifecycle()).d.a(B.d)) {
                        onStart(this.b);
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @InterfaceC1238a0(A.ON_DESTROY)
    public void onDestroy(@NonNull J j) {
        synchronized (this.a) {
            androidx.camera.core.internal.g gVar = this.c;
            gVar.z((ArrayList) gVar.w());
        }
    }

    @InterfaceC1238a0(A.ON_PAUSE)
    public void onPause(@NonNull J j) {
        this.c.a.i(false);
    }

    @InterfaceC1238a0(A.ON_RESUME)
    public void onResume(@NonNull J j) {
        this.c.a.i(true);
    }

    @InterfaceC1238a0(A.ON_START)
    public void onStart(@NonNull J j) {
        synchronized (this.a) {
            try {
                if (!this.d) {
                    this.c.d();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @InterfaceC1238a0(A.ON_STOP)
    public void onStop(@NonNull J j) {
        synchronized (this.a) {
            try {
                if (!this.d) {
                    this.c.s();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
