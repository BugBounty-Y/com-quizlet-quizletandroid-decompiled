package androidx.camera.core.imagecapture;

import androidx.camera.camera2.internal.T;
import androidx.camera.core.C0157i;
import androidx.camera.core.C0187j;
import androidx.camera.core.impl.utils.f;
import androidx.camera.core.processing.h;
import androidx.camera.core.processing.k;
import androidx.concurrent.futures.i;
import androidx.work.impl.model.v;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import java.util.Map;

/* loaded from: classes.dex */
public final /* synthetic */ class c implements androidx.core.util.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.core.util.a
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                ((v) this.b).getClass();
                S.d();
                break;
            case 1:
                C0187j c0187j = (C0187j) obj;
                for (Map.Entry entry : ((Map) this.b).entrySet()) {
                    int i = c0187j.b - ((androidx.camera.core.processing.util.b) entry.getKey()).f;
                    if (((androidx.camera.core.processing.util.b) entry.getKey()).g) {
                        i = -i;
                    }
                    int iF = f.f(i);
                    k kVar = (k) entry.getValue();
                    kVar.getClass();
                    S.g(new h(kVar, iF, -1));
                }
                break;
            case 2:
                AbstractC3053s1.f(3, "SurfaceViewImpl");
                T t = (T) this.b;
                if (t != null) {
                    t.k();
                    break;
                }
                break;
            default:
                ((i) this.b).b((C0157i) obj);
                break;
        }
    }
}
