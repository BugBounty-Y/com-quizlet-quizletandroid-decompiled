package androidx.navigation;

import androidx.lifecycle.B0;
import androidx.lifecycle.w0;
import java.util.Iterator;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.navigation.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1296s extends w0 {
    public final LinkedHashMap b = new LinkedHashMap();

    public final String toString() {
        StringBuilder sb = new StringBuilder("NavControllerViewModel{");
        int iIdentityHashCode = System.identityHashCode(this);
        kotlin.z zVar = kotlin.A.b;
        sb.append(kotlin.text.J.c(iIdentityHashCode));
        sb.append("} ViewModelStores (");
        Iterator it2 = this.b.keySet().iterator();
        while (it2.hasNext()) {
            sb.append((String) it2.next());
            if (it2.hasNext()) {
                sb.append(", ");
            }
        }
        sb.append(')');
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    @Override // androidx.lifecycle.w0
    public final void z() {
        LinkedHashMap linkedHashMap = this.b;
        Iterator it2 = linkedHashMap.values().iterator();
        while (it2.hasNext()) {
            ((B0) it2.next()).a();
        }
        linkedHashMap.clear();
    }
}
