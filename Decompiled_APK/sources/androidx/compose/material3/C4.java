package androidx.compose.material3;

import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.InterfaceC0877z;
import kotlin.InterfaceC4938g;
import kotlin.jvm.internal.InterfaceC4953l;

/* loaded from: classes.dex */
public final /* synthetic */ class C4 implements InterfaceC0877z, InterfaceC4953l {
    public final /* synthetic */ kotlin.jvm.internal.z a;

    public C4(kotlin.jvm.internal.z zVar) {
        this.a = zVar;
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0877z
    public final /* synthetic */ long a() {
        return ((C0861v) this.a.invoke()).a;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof InterfaceC0877z) || !(obj instanceof InterfaceC4953l)) {
            return false;
        }
        return this.a.equals(((InterfaceC4953l) obj).getFunctionDelegate());
    }

    @Override // kotlin.jvm.internal.InterfaceC4953l
    public final InterfaceC4938g getFunctionDelegate() {
        return this.a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}
