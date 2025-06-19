package androidx.camera.camera2.internal;

import android.hardware.camera2.CameraDevice;
import androidx.activity.RunnableC0041m;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;

/* loaded from: classes.dex */
public final class N extends CameraDevice.StateCallback {
    public final /* synthetic */ int a;
    public final Object b;

    public N(c0 c0Var) {
        this.a = 1;
        this.b = c0Var;
    }

    private final void c(CameraDevice cameraDevice) {
    }

    public void a() {
        ArrayList arrayListQ;
        synchronized (((c0) this.b).c) {
            arrayListQ = ((c0) this.b).q();
            ((LinkedHashSet) ((c0) this.b).f).clear();
            ((LinkedHashSet) ((c0) this.b).d).clear();
            ((LinkedHashSet) ((c0) this.b).e).clear();
        }
        Iterator it2 = arrayListQ.iterator();
        while (it2.hasNext()) {
            k0 k0Var = (k0) it2.next();
            synchronized (k0Var.a) {
                try {
                    List list = k0Var.k;
                    if (list != null) {
                        Iterator it3 = list.iterator();
                        while (it3.hasNext()) {
                            ((androidx.camera.core.impl.J) it3.next()).b();
                        }
                        k0Var.k = null;
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
            k0Var.u.J();
        }
    }

    public void b() {
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        synchronized (((c0) this.b).c) {
            linkedHashSet.addAll((LinkedHashSet) ((c0) this.b).f);
            linkedHashSet.addAll((LinkedHashSet) ((c0) this.b).d);
        }
        ((androidx.camera.core.impl.utils.executor.k) ((c0) this.b).b).execute(new RunnableC0041m(linkedHashSet, 6));
    }

    @Override // android.hardware.camera2.CameraDevice.StateCallback
    public final void onClosed(CameraDevice cameraDevice) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((CameraDevice.StateCallback) it2.next()).onClosed(cameraDevice);
                }
                break;
            default:
                b();
                a();
                break;
        }
    }

    @Override // android.hardware.camera2.CameraDevice.StateCallback
    public final void onDisconnected(CameraDevice cameraDevice) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((CameraDevice.StateCallback) it2.next()).onDisconnected(cameraDevice);
                }
                break;
            default:
                b();
                a();
                break;
        }
    }

    @Override // android.hardware.camera2.CameraDevice.StateCallback
    public final void onError(CameraDevice cameraDevice, int i) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((CameraDevice.StateCallback) it2.next()).onError(cameraDevice, i);
                }
                return;
            default:
                b();
                LinkedHashSet linkedHashSet = new LinkedHashSet();
                synchronized (((c0) this.b).c) {
                    linkedHashSet.addAll((LinkedHashSet) ((c0) this.b).f);
                    linkedHashSet.addAll((LinkedHashSet) ((c0) this.b).d);
                }
                ((androidx.camera.core.impl.utils.executor.k) ((c0) this.b).b).execute(new RunnableC0133j(linkedHashSet, i, 1));
                a();
                return;
        }
    }

    @Override // android.hardware.camera2.CameraDevice.StateCallback
    public final void onOpened(CameraDevice cameraDevice) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((CameraDevice.StateCallback) it2.next()).onOpened(cameraDevice);
                }
                break;
        }
    }

    public N(ArrayList arrayList) {
        this.a = 0;
        this.b = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            CameraDevice.StateCallback stateCallback = (CameraDevice.StateCallback) it2.next();
            if (!(stateCallback instanceof O)) {
                ((ArrayList) this.b).add(stateCallback);
            }
        }
    }
}
