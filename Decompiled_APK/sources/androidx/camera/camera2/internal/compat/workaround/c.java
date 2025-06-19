package androidx.camera.camera2.internal.compat.workaround;

import androidx.camera.core.impl.J;
import com.google.android.gms.internal.ads.C2136hE;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class c {
    public boolean a;
    public boolean b;
    public boolean c;

    public /* synthetic */ c(boolean z, boolean z2, boolean z3) {
        this.a = z;
        this.b = z2;
        this.c = z3;
    }

    public boolean a() {
        return (this.c || this.b) && this.a;
    }

    public void b(ArrayList arrayList) {
        if ((this.a || this.b || this.c) && arrayList != null) {
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                ((J) it2.next()).a();
            }
            AbstractC3053s1.f(3, "ForceCloseDeferrableSurface");
        }
    }

    public C2136hE c() {
        if (this.a || !(this.b || this.c)) {
            return new C2136hE(this);
        }
        throw new IllegalStateException("Secondary offload attribute fields are true but primary isFormatSupported is false");
    }
}
