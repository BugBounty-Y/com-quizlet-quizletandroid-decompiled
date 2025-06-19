package androidx.activity.compose;

import kotlin.Unit;

/* loaded from: classes.dex */
public final class o extends androidx.activity.result.b {
    public final a a;

    public o(a aVar) {
        this.a = aVar;
    }

    @Override // androidx.activity.result.b
    public final void a(Object obj) throws Exception {
        Unit unit;
        androidx.activity.result.g gVar = this.a.a;
        if (gVar != null) {
            gVar.a(obj);
            unit = Unit.a;
        } else {
            unit = null;
        }
        if (unit == null) {
            throw new IllegalStateException("Launcher has not been initialized");
        }
    }
}
