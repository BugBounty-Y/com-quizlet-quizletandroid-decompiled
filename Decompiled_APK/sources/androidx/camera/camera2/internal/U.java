package androidx.camera.camera2.internal;

import android.hardware.camera2.CameraCaptureSession;
import android.view.Surface;
import androidx.activity.RunnableC0041m;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes.dex */
public final class U extends g0 {
    public final /* synthetic */ int a;
    public final Object b;

    public U(List list, int i) {
        this.a = i;
        switch (i) {
            case 2:
                ArrayList arrayList = new ArrayList();
                this.b = arrayList;
                arrayList.addAll(list);
                break;
            default:
                this.b = list.isEmpty() ? new M() : list.size() == 1 ? (CameraCaptureSession.StateCallback) list.get(0) : new L(list);
                break;
        }
    }

    private final void i(k0 k0Var) {
    }

    @Override // androidx.camera.camera2.internal.g0
    public void a(k0 k0Var) {
        switch (this.a) {
            case 1:
                ((CameraCaptureSession.StateCallback) this.b).onActive((CameraCaptureSession) ((com.quizlet.data.repository.searchexplanations.c) k0Var.r().a).b);
                break;
            case 2:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((g0) it2.next()).a(k0Var);
                }
                break;
        }
    }

    @Override // androidx.camera.camera2.internal.g0
    public void b(k0 k0Var) {
        switch (this.a) {
            case 1:
                ((CameraCaptureSession.StateCallback) this.b).onCaptureQueueEmpty((CameraCaptureSession) ((com.quizlet.data.repository.searchexplanations.c) k0Var.r().a).b);
                break;
            case 2:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((g0) it2.next()).b(k0Var);
                }
                break;
        }
    }

    @Override // androidx.camera.camera2.internal.g0
    public void c(k0 k0Var) {
        switch (this.a) {
            case 1:
                ((CameraCaptureSession.StateCallback) this.b).onClosed((CameraCaptureSession) ((com.quizlet.data.repository.searchexplanations.c) k0Var.r().a).b);
                break;
            case 2:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((g0) it2.next()).c(k0Var);
                }
                break;
        }
    }

    @Override // androidx.camera.camera2.internal.g0
    public final void d(k0 k0Var) {
        switch (this.a) {
            case 0:
                synchronized (((V) this.b).a) {
                    try {
                        switch (AbstractC0147y.k(((V) this.b).i)) {
                            case 0:
                            case 1:
                            case 2:
                            case 4:
                                throw new IllegalStateException("onConfigureFailed() should not be possible in state: ".concat(AbstractC0147y.m(((V) this.b).i)));
                            case 3:
                            case 5:
                            case 6:
                                ((V) this.b).d();
                                break;
                            case 7:
                                AbstractC3053s1.f(3, "CaptureSession");
                                break;
                        }
                        AbstractC3053s1.c("CaptureSession", "CameraCaptureSession.onConfigureFailed() ".concat(AbstractC0147y.m(((V) this.b).i)));
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return;
            case 1:
                ((CameraCaptureSession.StateCallback) this.b).onConfigureFailed((CameraCaptureSession) ((com.quizlet.data.repository.searchexplanations.c) k0Var.r().a).b);
                return;
            default:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((g0) it2.next()).d(k0Var);
                }
                return;
        }
    }

    @Override // androidx.camera.camera2.internal.g0
    public final void e(k0 k0Var) {
        switch (this.a) {
            case 0:
                synchronized (((V) this.b).a) {
                    try {
                        switch (AbstractC0147y.k(((V) this.b).i)) {
                            case 0:
                            case 1:
                            case 2:
                            case 4:
                            case 7:
                                throw new IllegalStateException("onConfigured() should not be possible in state: ".concat(AbstractC0147y.m(((V) this.b).i)));
                            case 3:
                                V v = (V) this.b;
                                v.i = 5;
                                v.e = k0Var;
                                AbstractC3053s1.f(3, "CaptureSession");
                                V v2 = (V) this.b;
                                v2.k(v2.f);
                                V v3 = (V) this.b;
                                v3.o.r().a(new RunnableC0041m(v3, 5), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
                                break;
                            case 5:
                                ((V) this.b).e = k0Var;
                                break;
                            case 6:
                                k0Var.j();
                                break;
                        }
                        int i = ((V) this.b).i;
                        AbstractC3053s1.f(3, "CaptureSession");
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return;
            case 1:
                ((CameraCaptureSession.StateCallback) this.b).onConfigured((CameraCaptureSession) ((com.quizlet.data.repository.searchexplanations.c) k0Var.r().a).b);
                return;
            default:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((g0) it2.next()).e(k0Var);
                }
                return;
        }
    }

    @Override // androidx.camera.camera2.internal.g0
    public final void f(k0 k0Var) {
        switch (this.a) {
            case 0:
                synchronized (((V) this.b).a) {
                    try {
                        if (AbstractC0147y.k(((V) this.b).i) == 0) {
                            throw new IllegalStateException("onReady() should not be possible in state: ".concat(AbstractC0147y.m(((V) this.b).i)));
                        }
                        int i = ((V) this.b).i;
                        AbstractC3053s1.f(3, "CaptureSession");
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return;
            case 1:
                ((CameraCaptureSession.StateCallback) this.b).onReady((CameraCaptureSession) ((com.quizlet.data.repository.searchexplanations.c) k0Var.r().a).b);
                return;
            default:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((g0) it2.next()).f(k0Var);
                }
                return;
        }
    }

    @Override // androidx.camera.camera2.internal.g0
    public final void g(k0 k0Var) {
        switch (this.a) {
            case 0:
                synchronized (((V) this.b).a) {
                    try {
                        if (((V) this.b).i == 1) {
                            throw new IllegalStateException("onSessionFinished() should not be possible in state: ".concat(AbstractC0147y.m(((V) this.b).i)));
                        }
                        AbstractC3053s1.f(3, "CaptureSession");
                        ((V) this.b).d();
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return;
            case 1:
                return;
            default:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((g0) it2.next()).g(k0Var);
                }
                return;
        }
    }

    @Override // androidx.camera.camera2.internal.g0
    public void h(k0 k0Var, Surface surface) {
        switch (this.a) {
            case 1:
                ((CameraCaptureSession.StateCallback) this.b).onSurfacePrepared((CameraCaptureSession) ((com.quizlet.data.repository.searchexplanations.c) k0Var.r().a).b, surface);
                break;
            case 2:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((g0) it2.next()).h(k0Var, surface);
                }
                break;
        }
    }

    public U(V v) {
        this.a = 0;
        this.b = v;
    }
}
