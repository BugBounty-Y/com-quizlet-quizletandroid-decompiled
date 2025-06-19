package androidx.work.impl.utils;

import androidx.work.z;
import java.util.Objects;

/* loaded from: classes.dex */
public final class t implements Runnable {
    public final u a;
    public final androidx.work.impl.model.j b;

    public t(u uVar, androidx.work.impl.model.j jVar) {
        this.a = uVar;
        this.b = jVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        synchronized (this.a.d) {
            try {
                if (((t) this.a.b.remove(this.b)) != null) {
                    s sVar = (s) this.a.c.remove(this.b);
                    if (sVar != null) {
                        androidx.work.impl.model.j jVar = this.b;
                        androidx.work.impl.background.systemalarm.f fVar = (androidx.work.impl.background.systemalarm.f) sVar;
                        z zVarC = z.c();
                        Objects.toString(jVar);
                        zVarC.getClass();
                        fVar.h.execute(new androidx.work.impl.background.systemalarm.e(fVar, 0));
                    }
                } else {
                    z zVarC2 = z.c();
                    Objects.toString(this.b);
                    zVarC2.getClass();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
