package androidx.compose.ui.draw;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class d implements androidx.compose.ui.unit.b {
    public b a = i.a;
    public com.google.firebase.platforminfo.c b;

    @Override // androidx.compose.ui.unit.b
    public final float Z() {
        return this.a.a().Z();
    }

    @Override // androidx.compose.ui.unit.b
    public final float a() {
        return this.a.a().a();
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final com.google.firebase.platforminfo.c b(Function1 function1) {
        com.google.firebase.platforminfo.c cVar = new com.google.firebase.platforminfo.c();
        cVar.a = (r) function1;
        this.b = cVar;
        return cVar;
    }
}
