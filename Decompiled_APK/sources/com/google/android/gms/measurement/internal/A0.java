package com.google.android.gms.measurement.internal;

import android.app.job.JobParameters;
import android.content.ComponentName;
import android.os.RemoteException;
import androidx.appcompat.view.menu.RunnableC0069f;
import androidx.appcompat.widget.C0122z;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3282v5;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3298x5;
import com.google.android.gms.internal.mlkit_vision_barcode.I5;
import com.google.android.gms.internal.mlkit_vision_barcode.J7;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.RuntimeExecutionException;
import com.google.android.gms.tasks.Task;
import com.perimeterx.mobile_sdk.doctor_app.ui.PXDoctorActivity;
import java.lang.ref.ReferenceQueue;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlinx.coroutines.C4975b0;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.DispatchException;

/* loaded from: classes2.dex */
public final class A0 implements Runnable {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ A0(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj2;
        this.c = obj;
    }

    @Override // java.lang.Runnable
    public final void run() throws DispatchException {
        boolean z = false;
        switch (this.a) {
            case 0:
                ((D0) this.c).p0((Boolean) this.b, true);
                return;
            case 1:
                D0 d0 = ((AppMeasurementDynamiteService) this.c).a.p;
                Y.j(d0);
                d0.k0((androidx.work.impl.model.l) this.b);
                return;
            case 2:
                Y0 y0 = (Y0) this.c;
                InterfaceC3897v interfaceC3897v = y0.e;
                Y y = (Y) y0.b;
                if (interfaceC3897v == null) {
                    I i = y.i;
                    Y.k(i);
                    i.g.f("Failed to send current screen to service");
                    return;
                }
                try {
                    L0 l0 = (L0) this.b;
                    if (l0 == null) {
                        interfaceC3897v.Z3(0L, null, null, y.a.getPackageName());
                    } else {
                        interfaceC3897v.Z3(l0.c, l0.a, l0.b, y.a.getPackageName());
                    }
                    y0.h0();
                    return;
                } catch (RemoteException e) {
                    I i2 = ((Y) y0.b).i;
                    Y.k(i2);
                    i2.g.g("Failed to send current screen to the service", e);
                    return;
                }
            case 3:
                Y0.k0(((X0) this.c).c, (ComponentName) this.b);
                return;
            case 4:
                Y0 y02 = ((X0) this.c).c;
                y02.e = null;
                if (!((Y) y02.b).g.f0(null, AbstractC3893t.o1) || ((ConnectionResult) this.b).b != 7777) {
                    y02.g0();
                    return;
                }
                if (y02.h == null) {
                    y02.h = Executors.newScheduledThreadPool(1);
                }
                y02.h.schedule(new com.google.android.gms.common.api.internal.w(this, 4), ((Long) AbstractC3893t.Y.a(null)).longValue(), TimeUnit.MILLISECONDS);
                return;
            case 5:
                ((b1) ((c1) this.b).a).c((JobParameters) this.c);
                return;
            case 6:
                Task task = (Task) this.b;
                boolean zJ = task.j();
                com.google.android.gms.tasks.i iVar = (com.google.android.gms.tasks.i) this.c;
                if (zJ) {
                    iVar.d.s();
                    return;
                }
                try {
                    iVar.d.p(iVar.c.h(task));
                    return;
                } catch (RuntimeExecutionException e2) {
                    if (e2.getCause() instanceof Exception) {
                        iVar.d.r((Exception) e2.getCause());
                        return;
                    } else {
                        iVar.d.r(e2);
                        return;
                    }
                } catch (Exception e3) {
                    iVar.d.r(e3);
                    return;
                }
            case 7:
                com.google.android.gms.tasks.j jVar = (com.google.android.gms.tasks.j) this.c;
                synchronized (jVar.c) {
                    try {
                        OnCompleteListener onCompleteListener = (OnCompleteListener) jVar.d;
                        if (onCompleteListener != null) {
                            onCompleteListener.onComplete((Task) this.b);
                        }
                    } finally {
                    }
                }
                return;
            case 8:
                com.google.android.gms.tasks.j jVar2 = (com.google.android.gms.tasks.j) this.c;
                synchronized (jVar2.c) {
                    try {
                        com.google.android.gms.tasks.d dVar = (com.google.android.gms.tasks.d) jVar2.d;
                        if (dVar != null) {
                            dVar.onSuccess(((Task) this.b).h());
                        }
                    } finally {
                    }
                }
                return;
            case 9:
                com.google.android.gms.tasks.m mVar = (com.google.android.gms.tasks.m) this.b;
                try {
                    mVar.p(((Callable) this.c).call());
                    return;
                } catch (Exception e4) {
                    mVar.r(e4);
                    return;
                } catch (Throwable th) {
                    mVar.r(new RuntimeException(th));
                    return;
                }
            case 10:
                ReferenceQueue referenceQueue = (ReferenceQueue) this.b;
                while (!((Set) this.c).isEmpty()) {
                    try {
                        com.google.mlkit.common.sdkinternal.j jVar3 = (com.google.mlkit.common.sdkinternal.j) referenceQueue.remove();
                        if (jVar3.a.remove(jVar3)) {
                            jVar3.clear();
                            jVar3.b.getClass();
                        }
                    } catch (InterruptedException unused) {
                    }
                }
                return;
            case 11:
                com.google.mlkit.vision.barcode.internal.e eVar = (com.google.mlkit.vision.barcode.internal.e) this.b;
                com.google.android.gms.tasks.f fVar = (com.google.android.gms.tasks.f) this.c;
                int iDecrementAndGet = eVar.b.decrementAndGet();
                com.google.android.gms.common.internal.u.k(iDecrementAndGet >= 0);
                if (iDecrementAndGet == 0) {
                    synchronized (eVar) {
                        try {
                            eVar.e.zzb();
                            com.google.mlkit.vision.barcode.internal.e.j = true;
                            androidx.camera.camera2.internal.c0 c0Var = new androidx.camera.camera2.internal.c0(9, z);
                            EnumC3282v5 enumC3282v5 = eVar.i ? EnumC3282v5.TYPE_THICK : EnumC3282v5.TYPE_THIN;
                            J7 j7 = eVar.f;
                            c0Var.d = enumC3282v5;
                            C1608n c1608n = new C1608n();
                            c1608n.b = com.google.mlkit.vision.barcode.internal.a.a(eVar.d);
                            c0Var.e = new I5(c1608n);
                            com.google.mlkit.common.sdkinternal.k.a.execute(new RunnableC0069f(12, j7, new C0122z(c0Var, 0), EnumC3298x5.ON_DEVICE_BARCODE_CLOSE, j7.c(), false));
                        } finally {
                        }
                    }
                    eVar.c.set(false);
                }
                com.google.android.gms.internal.mlkit_common.n.a.clear();
                com.google.android.gms.internal.mlkit_common.t.a.clear();
                fVar.b(null);
                return;
            case 12:
                if (((com.google.mlkit.vision.camera.internal.a) this.b).b.get()) {
                    return;
                }
                ((Runnable) this.c).run();
                return;
            case 13:
                com.google.android.gms.internal.mlkit_common.u uVar = PXDoctorActivity.e;
                ((PXDoctorActivity) this.b).r(false, (Function0) this.c);
                return;
            case 14:
                ((io.reactivex.rxjava3.internal.operators.observable.m0) this.c).a.c((io.reactivex.rxjava3.internal.operators.mixed.a) this.b);
                return;
            case 15:
                ((C5028l) this.c).E((C4975b0) this.b, Unit.a);
                return;
            default:
                kotlin.coroutines.h hVarB = kotlin.coroutines.intrinsics.h.b((retrofit2.r) this.b);
                kotlin.p pVar = kotlin.r.b;
                hVarB.resumeWith(androidx.glance.appwidget.protobuf.Z.b((Throwable) this.c));
                return;
        }
    }

    public /* synthetic */ A0(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }
}
