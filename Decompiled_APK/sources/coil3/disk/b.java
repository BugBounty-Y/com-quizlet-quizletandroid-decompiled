package coil3.disk;

import kotlin.Unit;

/* loaded from: classes.dex */
public final class b implements AutoCloseable {
    public final a a;
    public boolean b;
    public final /* synthetic */ e c;

    public b(e eVar, a aVar) {
        this.c = eVar;
        this.a = aVar;
    }

    @Override // java.lang.AutoCloseable
    public final void close() {
        if (this.b) {
            return;
        }
        this.b = true;
        e eVar = this.c;
        synchronized (eVar.h) {
            a aVar = this.a;
            int i = aVar.h - 1;
            aVar.h = i;
            if (i == 0 && aVar.f) {
                eVar.y(aVar);
            }
            Unit unit = Unit.a;
        }
    }
}
