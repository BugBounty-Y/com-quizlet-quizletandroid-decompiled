package androidx.camera.camera2.internal;

import android.util.ArrayMap;
import androidx.activity.RunnableC0043o;
import androidx.camera.core.impl.AbstractC0171j;
import androidx.camera.core.impl.InterfaceC0177p;
import androidx.camera.core.impl.InterfaceC0183w;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import java.util.HashSet;
import java.util.Iterator;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

/* renamed from: androidx.camera.camera2.internal.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0134k extends AbstractC0171j {
    public final /* synthetic */ int a = 0;
    public Object b;
    public Object c;

    public /* synthetic */ C0134k() {
    }

    @Override // androidx.camera.core.impl.AbstractC0171j
    public void a(int i) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((HashSet) this.b).iterator();
                while (it2.hasNext()) {
                    AbstractC0171j abstractC0171j = (AbstractC0171j) it2.next();
                    try {
                        ((Executor) ((ArrayMap) this.c).get(abstractC0171j)).execute(new RunnableC0133j(abstractC0171j, i, 0));
                    } catch (RejectedExecutionException e) {
                        AbstractC3053s1.d("Camera2CameraControlImp", "Executor rejected to invoke onCaptureCancelled.", e);
                    }
                }
                break;
        }
    }

    @Override // androidx.camera.core.impl.AbstractC0171j
    public final void b(int i, InterfaceC0177p interfaceC0177p) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((HashSet) this.b).iterator();
                while (it2.hasNext()) {
                    AbstractC0171j abstractC0171j = (AbstractC0171j) it2.next();
                    try {
                        ((Executor) ((ArrayMap) this.c).get(abstractC0171j)).execute(new RunnableC0043o(abstractC0171j, i, interfaceC0177p, 3));
                    } catch (RejectedExecutionException e) {
                        AbstractC3053s1.d("Camera2CameraControlImp", "Executor rejected to invoke onCaptureCompleted.", e);
                    }
                }
                break;
            default:
                ((androidx.concurrent.futures.i) this.b).b(null);
                ((InterfaceC0183w) this.c).j(this);
                break;
        }
    }

    @Override // androidx.camera.core.impl.AbstractC0171j
    public void c(int i, assistantMode.utils.studiableMetadata.b bVar) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((HashSet) this.b).iterator();
                while (it2.hasNext()) {
                    AbstractC0171j abstractC0171j = (AbstractC0171j) it2.next();
                    try {
                        ((Executor) ((ArrayMap) this.c).get(abstractC0171j)).execute(new RunnableC0043o(abstractC0171j, i, bVar, 2));
                    } catch (RejectedExecutionException e) {
                        AbstractC3053s1.d("Camera2CameraControlImp", "Executor rejected to invoke onCaptureFailed.", e);
                    }
                }
                break;
        }
    }

    public C0134k(androidx.concurrent.futures.i iVar, InterfaceC0183w interfaceC0183w) {
        this.b = iVar;
        this.c = interfaceC0183w;
    }
}
