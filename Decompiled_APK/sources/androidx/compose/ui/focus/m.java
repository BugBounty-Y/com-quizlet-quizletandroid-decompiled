package androidx.compose.ui.focus;

import kotlin.InterfaceC4938g;
import kotlin.jvm.internal.InterfaceC4953l;

/* loaded from: classes.dex */
public final /* synthetic */ class m implements InterfaceC4953l {
    public final boolean equals(Object obj) {
        if (!(obj instanceof m) || obj == null) {
            return false;
        }
        return i.b.equals(((InterfaceC4953l) obj).getFunctionDelegate());
    }

    @Override // kotlin.jvm.internal.InterfaceC4953l
    public final InterfaceC4938g getFunctionDelegate() {
        return i.b;
    }

    public final int hashCode() {
        return i.b.hashCode();
    }
}
