package androidx.camera.core.impl;

import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CaptureRequest;
import android.util.Rational;
import android.util.Size;
import androidx.camera.camera2.internal.compat.quirk.PreviewPixelHDRnetQuirk;
import androidx.camera.core.C0196t;
import com.google.android.gms.ads.internal.client.C1608n;
import java.util.ArrayList;
import java.util.HashSet;

/* loaded from: classes.dex */
public final class m0 extends l0 {
    public static m0 d(A0 a0, Size size) {
        if (((androidx.camera.camera2.internal.J) a0.j(A0.p0, null)) == null) {
            throw new IllegalStateException("Implementation is missing option unpacker for " + ((String) a0.j(androidx.camera.core.internal.k.z0, a0.toString())));
        }
        m0 m0Var = new m0();
        q0 q0Var = (q0) a0.j(A0.n0, null);
        C0163c0 c0163c0 = C0163c0.c;
        int i = q0.a().g.c;
        if (q0Var != null) {
            i = q0Var.g.c;
            for (CameraDevice.StateCallback stateCallback : q0Var.c) {
                ArrayList arrayList = m0Var.c;
                if (!arrayList.contains(stateCallback)) {
                    arrayList.add(stateCallback);
                }
            }
            for (CameraCaptureSession.StateCallback stateCallback2 : q0Var.d) {
                ArrayList arrayList2 = m0Var.d;
                if (!arrayList2.contains(stateCallback2)) {
                    arrayList2.add(stateCallback2);
                }
            }
            m0Var.b.a(q0Var.g.d);
            c0163c0 = q0Var.g.b;
        }
        androidx.camera.core.a0 a0Var = m0Var.b;
        a0Var.getClass();
        a0Var.d = X.k(c0163c0);
        if (a0 instanceof C0165d0) {
            Rational rational = androidx.camera.camera2.internal.compat.workaround.d.a;
            if (((PreviewPixelHDRnetQuirk) androidx.camera.camera2.internal.compat.quirk.b.a.b(PreviewPixelHDRnetQuirk.class)) != null && !androidx.camera.camera2.internal.compat.workaround.d.a.equals(new Rational(size.getWidth(), size.getHeight()))) {
                X xB = X.b();
                xB.m(androidx.camera.camera2.impl.b.U(CaptureRequest.TONEMAP_MODE), 2);
                m0Var.b.d(new androidx.camera.camera2.impl.b(C0163c0.a(xB), 4));
            }
        }
        m0Var.b.a = ((Integer) a0.j(androidx.camera.camera2.impl.b.c, Integer.valueOf(i))).intValue();
        CameraDevice.StateCallback stateCallback3 = (CameraDevice.StateCallback) a0.j(androidx.camera.camera2.impl.b.e, new androidx.camera.camera2.internal.O());
        ArrayList arrayList3 = m0Var.c;
        if (!arrayList3.contains(stateCallback3)) {
            arrayList3.add(stateCallback3);
        }
        CameraCaptureSession.StateCallback stateCallback4 = (CameraCaptureSession.StateCallback) a0.j(androidx.camera.camera2.impl.b.f, new androidx.camera.camera2.internal.M());
        ArrayList arrayList4 = m0Var.d;
        if (!arrayList4.contains(stateCallback4)) {
            arrayList4.add(stateCallback4);
        }
        androidx.camera.camera2.internal.P p = new androidx.camera.camera2.internal.P((CameraCaptureSession.CaptureCallback) a0.j(androidx.camera.camera2.impl.b.g, new androidx.camera.camera2.internal.H()));
        m0Var.b.c(p);
        ArrayList arrayList5 = m0Var.e;
        if (!arrayList5.contains(p)) {
            arrayList5.add(p);
        }
        C0162c c0162c = A0.x0;
        Integer num = (Integer) a0.j(c0162c, 0);
        int iIntValue = num.intValue();
        if (iIntValue != 0) {
            androidx.camera.core.a0 a0Var2 = m0Var.b;
            a0Var2.getClass();
            if (iIntValue != 0) {
                ((X) a0Var2.d).m(c0162c, num);
            }
        }
        int iA = a0.A();
        if (iA != 0) {
            androidx.camera.core.a0 a0Var3 = m0Var.b;
            a0Var3.getClass();
            if (iA != 0) {
                ((X) a0Var3.d).m(A0.w0, Integer.valueOf(iA));
            }
        }
        X xB2 = X.b();
        C0162c c0162c2 = androidx.camera.camera2.impl.b.h;
        xB2.m(c0162c2, (String) a0.j(c0162c2, null));
        C0162c c0162c3 = androidx.camera.camera2.impl.b.d;
        Long l = (Long) a0.j(c0162c3, -1L);
        l.getClass();
        xB2.m(c0162c3, l);
        m0Var.b.d(xB2);
        m0Var.b.d(com.google.firebase.platforminfo.c.l(a0).h());
        return m0Var;
    }

    public final void a(H h) {
        this.b.d(h);
    }

    public final void b(J j, C0196t c0196t, int i) {
        C1608n c1608nA = C0166e.a(j);
        if (c0196t == null) {
            throw new NullPointerException("Null dynamicRange");
        }
        c1608nA.e = c0196t;
        c1608nA.c = Integer.valueOf(i);
        this.a.add(c1608nA.i());
        ((HashSet) this.b.c).add(j);
    }

    public final q0 c() {
        return new q0(new ArrayList(this.a), new ArrayList(this.c), new ArrayList(this.d), new ArrayList(this.e), this.b.e(), this.f, this.g, this.h);
    }
}
