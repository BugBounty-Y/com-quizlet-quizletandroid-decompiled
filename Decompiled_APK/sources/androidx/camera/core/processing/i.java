package androidx.camera.core.processing;

import android.view.Surface;
import androidx.camera.core.C0155g;
import androidx.camera.core.impl.DeferrableSurface$SurfaceClosedException;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.T;

/* loaded from: classes.dex */
public final /* synthetic */ class i implements androidx.camera.core.impl.utils.futures.a {
    public final /* synthetic */ k a;
    public final /* synthetic */ j b;
    public final /* synthetic */ int c;
    public final /* synthetic */ C0155g d;
    public final /* synthetic */ C0155g e;

    public /* synthetic */ i(k kVar, j jVar, int i, C0155g c0155g, C0155g c0155g2) {
        this.a = kVar;
        this.b = jVar;
        this.c = i;
        this.d = c0155g;
        this.e = c0155g2;
    }

    @Override // androidx.camera.core.impl.utils.futures.a, com.google.android.datatransport.runtime.scheduling.persistence.e, io.reactivex.rxjava3.functions.h
    public final com.google.common.util.concurrent.e apply(Object obj) {
        j jVar = this.b;
        Surface surface = (Surface) obj;
        k kVar = this.a;
        kVar.getClass();
        surface.getClass();
        try {
            jVar.d();
            l lVar = new l(surface, this.c, kVar.g.a, this.d, this.e);
            lVar.j.b.a(new g(jVar, 1), T.a());
            AbstractC3242q6.h("Consumer can only be linked once.", jVar.r == null);
            jVar.r = lVar;
            return androidx.camera.core.impl.utils.futures.i.c(lVar);
        } catch (DeferrableSurface$SurfaceClosedException e) {
            return new androidx.camera.core.impl.utils.futures.k(e, 1);
        }
    }
}
