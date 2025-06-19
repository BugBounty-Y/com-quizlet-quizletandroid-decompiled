package androidx.camera.camera2.internal;

import android.graphics.SurfaceTexture;
import android.hardware.camera2.CameraDevice;
import android.os.Handler;
import android.util.ArrayMap;
import android.view.Surface;
import androidx.activity.RunnableC0041m;
import androidx.activity.RunnableC0043o;
import androidx.camera.core.C0196t;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.C0166e;
import androidx.camera.core.impl.v0;
import com.amazon.device.ads.DtbConstants;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Objects;

/* renamed from: androidx.camera.camera2.internal.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0144v extends CameraDevice.StateCallback {
    public final /* synthetic */ int a = 0;
    public final Object b;
    public final Object c;

    public C0144v(androidx.camera.core.impl.utils.executor.k kVar, CameraDevice.StateCallback stateCallback) {
        this.c = kVar;
        this.b = stateCallback;
    }

    @Override // android.hardware.camera2.CameraDevice.StateCallback
    public final void onClosed(CameraDevice cameraDevice) {
        switch (this.a) {
            case 0:
                ((C) this.c).t("openCameraConfigAndClose camera closed");
                ((androidx.concurrent.futures.i) this.b).b(null);
                break;
            default:
                ((androidx.camera.core.impl.utils.executor.k) this.c).execute(new androidx.camera.camera2.internal.compat.l(this, cameraDevice, 0));
                break;
        }
    }

    @Override // android.hardware.camera2.CameraDevice.StateCallback
    public final void onDisconnected(CameraDevice cameraDevice) {
        switch (this.a) {
            case 0:
                ((C) this.c).t("openCameraConfigAndClose camera disconnected");
                ((androidx.concurrent.futures.i) this.b).b(null);
                break;
            default:
                ((androidx.camera.core.impl.utils.executor.k) this.c).execute(new androidx.camera.camera2.internal.compat.l(this, cameraDevice, 1));
                break;
        }
    }

    @Override // android.hardware.camera2.CameraDevice.StateCallback
    public final void onError(CameraDevice cameraDevice, int i) {
        switch (this.a) {
            case 0:
                ((C) this.c).t(android.support.v4.media.session.a.f(i, "openCameraConfigAndClose camera error "));
                ((androidx.concurrent.futures.i) this.b).b(null);
                break;
            default:
                ((androidx.camera.core.impl.utils.executor.k) this.c).execute(new RunnableC0043o(this, cameraDevice, i, 5));
                break;
        }
    }

    @Override // android.hardware.camera2.CameraDevice.StateCallback
    public final void onOpened(CameraDevice cameraDevice) {
        Object obj = this.c;
        switch (this.a) {
            case 0:
                C c = (C) obj;
                c.t("openCameraConfigAndClose camera opened");
                V v = new V(c.E, new androidx.camera.core.impl.i0(Collections.EMPTY_LIST), false);
                SurfaceTexture surfaceTexture = new SurfaceTexture(0);
                surfaceTexture.setDefaultBufferSize(640, DtbConstants.DEFAULT_PLAYER_HEIGHT);
                Surface surface = new Surface(surfaceTexture);
                androidx.camera.core.g0 g0Var = new androidx.camera.core.g0(surface);
                androidx.camera.core.impl.utils.futures.i.d(g0Var.e).a(new androidx.activity.r(6, surface, surfaceTexture), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
                LinkedHashSet linkedHashSet = new LinkedHashSet();
                HashSet hashSet = new HashSet();
                androidx.camera.core.impl.X xB = androidx.camera.core.impl.X.b();
                ArrayList arrayList = new ArrayList();
                androidx.camera.core.impl.Z zA = androidx.camera.core.impl.Z.a();
                ArrayList arrayList2 = new ArrayList();
                ArrayList arrayList3 = new ArrayList();
                ArrayList arrayList4 = new ArrayList();
                C0196t c0196t = C0196t.d;
                C1608n c1608nA = C0166e.a(g0Var);
                c1608nA.e = c0196t;
                linkedHashSet.add(c1608nA.i());
                c.t("Start configAndClose.");
                ArrayList arrayList5 = new ArrayList(linkedHashSet);
                ArrayList arrayList6 = new ArrayList(arrayList2);
                ArrayList arrayList7 = new ArrayList(arrayList3);
                ArrayList arrayList8 = new ArrayList(arrayList4);
                ArrayList arrayList9 = new ArrayList(hashSet);
                C0163c0 c0163c0A = C0163c0.a(xB);
                ArrayList arrayList10 = new ArrayList(arrayList);
                v0 v0Var = v0.b;
                ArrayMap arrayMap = new ArrayMap();
                ArrayMap arrayMap2 = zA.a;
                for (String str : arrayMap2.keySet()) {
                    arrayMap.put(str, arrayMap2.get(str));
                }
                androidx.camera.core.impl.q0 q0Var = new androidx.camera.core.impl.q0(arrayList5, arrayList6, arrayList7, arrayList8, new androidx.camera.core.impl.F(arrayList9, c0163c0A, 1, arrayList10, false, new v0(arrayMap), null), null, null, null);
                c0 c0Var = c.y;
                androidx.camera.core.impl.utils.executor.e eVar = (androidx.camera.core.impl.utils.executor.e) c0Var.c;
                c0 c0Var2 = (c0) c0Var.e;
                androidx.camera.core.impl.utils.executor.k kVar = (androidx.camera.core.impl.utils.executor.k) c0Var.b;
                androidx.camera.core.impl.utils.futures.d dVarC = androidx.camera.core.impl.utils.futures.d.c(Y5.b(new androidx.camera.core.impl.utils.futures.g(0, v.l(q0Var, cameraDevice, new k0((Handler) c0Var.d, c0Var2, (androidx.camera.core.impl.i0) c0Var.f, (androidx.camera.core.impl.i0) c0Var.g, eVar, kVar)))));
                C0143u c0143u = new C0143u(0, v, g0Var);
                dVarC.getClass();
                androidx.camera.core.impl.utils.executor.k kVar2 = c.c;
                androidx.camera.core.impl.utils.futures.b bVarF = androidx.camera.core.impl.utils.futures.i.f(dVarC, c0143u, kVar2);
                Objects.requireNonNull(cameraDevice);
                bVarF.a(new RunnableC0041m(cameraDevice, 3), kVar2);
                break;
            default:
                ((androidx.camera.core.impl.utils.executor.k) obj).execute(new androidx.camera.camera2.internal.compat.l(this, cameraDevice, 2));
                break;
        }
    }

    public C0144v(C c, androidx.concurrent.futures.i iVar) {
        this.c = c;
        this.b = iVar;
    }
}
