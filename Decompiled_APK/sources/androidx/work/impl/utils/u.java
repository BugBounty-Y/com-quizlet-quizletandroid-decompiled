package androidx.work.impl.utils;

import androidx.work.z;
import java.util.HashMap;
import java.util.Objects;

/* loaded from: classes.dex */
public final class u {
    public final androidx.camera.camera2.internal.compat.h a;
    public final HashMap b = new HashMap();
    public final HashMap c = new HashMap();
    public final Object d = new Object();

    static {
        z.e("WorkTimer");
    }

    public u(androidx.camera.camera2.internal.compat.h hVar) {
        this.a = hVar;
    }

    public final void a(androidx.work.impl.model.j jVar) {
        synchronized (this.d) {
            try {
                if (((t) this.b.remove(jVar)) != null) {
                    z zVarC = z.c();
                    Objects.toString(jVar);
                    zVarC.getClass();
                    this.c.remove(jVar);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
