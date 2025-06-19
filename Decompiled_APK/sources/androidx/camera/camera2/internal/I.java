package androidx.camera.camera2.internal;

import android.hardware.camera2.CameraCaptureSession;
import android.util.ArrayMap;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.v0;
import java.util.ArrayList;
import java.util.HashSet;

/* loaded from: classes.dex */
public class I {
    public static final I a = new I();

    public void a(androidx.camera.core.impl.N n, androidx.camera.core.a0 a0Var) {
        androidx.camera.core.impl.F f = (androidx.camera.core.impl.F) n.j(A0.o0, null);
        C0163c0 c0163c0 = C0163c0.c;
        C0162c c0162c = androidx.camera.core.impl.F.h;
        HashSet hashSet = new HashSet();
        androidx.camera.core.impl.X xB = androidx.camera.core.impl.X.b();
        ArrayList arrayList = new ArrayList();
        androidx.camera.core.impl.Z zA = androidx.camera.core.impl.Z.a();
        ArrayList arrayList2 = new ArrayList(hashSet);
        C0163c0 c0163c0A = C0163c0.a(xB);
        ArrayList arrayList3 = new ArrayList(arrayList);
        v0 v0Var = v0.b;
        ArrayMap arrayMap = new ArrayMap();
        ArrayMap arrayMap2 = zA.a;
        for (String str : arrayMap2.keySet()) {
            arrayMap.put(str, arrayMap2.get(str));
        }
        int i = -1;
        new androidx.camera.core.impl.F(arrayList2, c0163c0A, -1, arrayList3, false, new v0(arrayMap), null);
        if (f != null) {
            a0Var.a(f.d);
            c0163c0 = f.b;
            i = f.c;
        }
        a0Var.d = androidx.camera.core.impl.X.k(c0163c0);
        a0Var.a = ((Integer) n.j(androidx.camera.camera2.impl.b.c, Integer.valueOf(i))).intValue();
        a0Var.c(new P((CameraCaptureSession.CaptureCallback) n.j(androidx.camera.camera2.impl.b.g, new H())));
        a0Var.d(com.google.firebase.platforminfo.c.l(n).h());
    }
}
