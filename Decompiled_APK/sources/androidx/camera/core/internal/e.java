package androidx.camera.core.internal;

import android.graphics.SurfaceTexture;
import android.view.Surface;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes.dex */
public final /* synthetic */ class e implements androidx.core.util.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ e(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // androidx.core.util.a
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                ((Surface) this.b).release();
                ((SurfaceTexture) this.c).release();
                break;
            case 1:
                androidx.camera.core.processing.c cVar = (androidx.camera.core.processing.c) this.b;
                cVar.getClass();
                androidx.camera.core.processing.l lVar = (androidx.camera.core.processing.l) this.c;
                lVar.close();
                Surface surface = (Surface) cVar.h.remove(lVar);
                if (surface != null) {
                    androidx.camera.core.processing.e eVar = cVar.a;
                    androidx.camera.core.processing.util.i.d((AtomicBoolean) eVar.c, true);
                    androidx.camera.core.processing.util.i.c((Thread) eVar.e);
                    eVar.q(surface, true);
                    break;
                }
                break;
            default:
                androidx.camera.core.processing.concurrent.e eVar2 = (androidx.camera.core.processing.concurrent.e) this.b;
                eVar2.getClass();
                androidx.camera.core.processing.l lVar2 = (androidx.camera.core.processing.l) this.c;
                lVar2.close();
                Surface surface2 = (Surface) eVar2.h.remove(lVar2);
                if (surface2 != null) {
                    androidx.camera.core.processing.concurrent.c cVar2 = eVar2.a;
                    androidx.camera.core.processing.util.i.d((AtomicBoolean) cVar2.c, true);
                    androidx.camera.core.processing.util.i.c((Thread) cVar2.e);
                    cVar2.q(surface2, true);
                    break;
                }
                break;
        }
    }
}
