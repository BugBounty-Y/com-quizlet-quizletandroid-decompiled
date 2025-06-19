package androidx.camera.camera2.internal;

import android.hardware.camera2.CameraCharacteristics;
import android.util.Log;
import android.util.Pair;
import android.util.Size;
import androidx.camera.core.C0152d;
import androidx.camera.core.impl.AbstractC0171j;
import androidx.camera.core.impl.InterfaceC0183w;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.measurement.T1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final class F implements InterfaceC0183w {
    public final String a;
    public final androidx.camera.camera2.internal.compat.k b;
    public final com.google.android.gms.internal.instantapps.a c;
    public C0137n e;
    public final E f;
    public final androidx.camera.core.impl.i0 h;
    public final Object d = new Object();
    public ArrayList g = null;

    public F(androidx.camera.camera2.internal.compat.q qVar, String str) throws NumberFormatException {
        str.getClass();
        this.a = str;
        androidx.camera.camera2.internal.compat.k kVarB = qVar.b(str);
        this.b = kVarB;
        com.google.android.gms.internal.instantapps.a aVar = new com.google.android.gms.internal.instantapps.a(5);
        aVar.b = this;
        this.c = aVar;
        this.h = com.google.android.exoplayer2.drm.b.l(kVarB);
        new HashMap();
        try {
            Integer.parseInt(str);
        } catch (NumberFormatException unused) {
            AbstractC3053s1.h("Camera2EncoderProfilesProvider", "Camera id is not an integer: " + str + ", unable to create Camera2EncoderProfilesProvider");
        }
        this.f = new E(new C0152d(5, null));
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public final int a() {
        return g(0);
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public final void b(androidx.camera.core.impl.utils.executor.a aVar, C0134k c0134k) {
        synchronized (this.d) {
            try {
                C0137n c0137n = this.e;
                if (c0137n != null) {
                    c0137n.c.execute(new RunnableC0130g(c0137n, aVar, c0134k, 0));
                } else {
                    if (this.g == null) {
                        this.g = new ArrayList();
                    }
                    this.g.add(new Pair(c0134k, aVar));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public final String c() {
        return this.a;
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public final int e() {
        Integer num = (Integer) this.b.a(CameraCharacteristics.LENS_FACING);
        AbstractC3242q6.c("Unable to get the lens facing of the camera.", num != null);
        int iIntValue = num.intValue();
        if (iIntValue == 0) {
            return 0;
        }
        if (iIntValue == 1) {
            return 1;
        }
        if (iIntValue == 2) {
            return 2;
        }
        throw new IllegalArgumentException(AbstractC0147y.c(iIntValue, "The given lens facing integer: ", " can not be recognized."));
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public final String f() {
        Integer num = (Integer) this.b.a(CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL);
        num.getClass();
        return num.intValue() == 2 ? "androidx.camera.camera2.legacy" : "androidx.camera.camera2";
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public final int g(int i) {
        Integer num = (Integer) this.b.a(CameraCharacteristics.SENSOR_ORIENTATION);
        num.getClass();
        return T1.a(T1.b(i), num.intValue(), 1 == e());
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public final androidx.camera.core.impl.i0 h() {
        return this.h;
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public final List i(int i) {
        Size[] sizeArrP = this.b.b().p(i);
        return sizeArrP != null ? Arrays.asList(sizeArrP) : Collections.EMPTY_LIST;
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public final void j(AbstractC0171j abstractC0171j) {
        synchronized (this.d) {
            try {
                C0137n c0137n = this.e;
                if (c0137n != null) {
                    c0137n.c.execute(new androidx.activity.r(3, c0137n, abstractC0171j));
                    return;
                }
                ArrayList arrayList = this.g;
                if (arrayList == null) {
                    return;
                }
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    if (((Pair) it2.next()).first == abstractC0171j) {
                        it2.remove();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void k(C0137n c0137n) {
        synchronized (this.d) {
            try {
                this.e = c0137n;
                ArrayList arrayList = this.g;
                if (arrayList != null) {
                    Iterator it2 = arrayList.iterator();
                    while (it2.hasNext()) {
                        Pair pair = (Pair) it2.next();
                        C0137n c0137n2 = this.e;
                        Executor executor = (Executor) pair.second;
                        AbstractC0171j abstractC0171j = (AbstractC0171j) pair.first;
                        c0137n2.getClass();
                        c0137n2.c.execute(new RunnableC0130g(c0137n2, executor, abstractC0171j, 0));
                    }
                    this.g = null;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        Integer num = (Integer) this.b.a(CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL);
        num.getClass();
        int iIntValue = num.intValue();
        String strD = AbstractC0147y.d("Device Level: ", iIntValue != 0 ? iIntValue != 1 ? iIntValue != 2 ? iIntValue != 3 ? iIntValue != 4 ? android.support.v4.media.session.a.f(iIntValue, "Unknown value: ") : "INFO_SUPPORTED_HARDWARE_LEVEL_EXTERNAL" : "INFO_SUPPORTED_HARDWARE_LEVEL_3" : "INFO_SUPPORTED_HARDWARE_LEVEL_LEGACY" : "INFO_SUPPORTED_HARDWARE_LEVEL_FULL" : "INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED");
        if (AbstractC3053s1.f(4, "Camera2CameraInfo")) {
            Log.i("Camera2CameraInfo", strD);
        }
    }
}
