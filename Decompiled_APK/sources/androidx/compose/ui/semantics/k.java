package androidx.compose.ui.semantics;

import androidx.compose.animation.d0;
import androidx.compose.ui.platform.N;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.InterfaceC4938g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class k implements v, Iterable, kotlin.jvm.internal.markers.a {
    public final LinkedHashMap a = new LinkedHashMap();
    public boolean b;
    public boolean c;

    public final Object a(u uVar) {
        Object obj = this.a.get(uVar);
        if (obj != null) {
            return obj;
        }
        throw new IllegalStateException("Key not present: " + uVar + " - consider getOrElse or getOrNull");
    }

    public final void b(u uVar, Object obj) {
        boolean z = obj instanceof a;
        LinkedHashMap linkedHashMap = this.a;
        if (!z || !linkedHashMap.containsKey(uVar)) {
            linkedHashMap.put(uVar, obj);
            return;
        }
        Object obj2 = linkedHashMap.get(uVar);
        Intrinsics.e(obj2, "null cannot be cast to non-null type androidx.compose.ui.semantics.AccessibilityAction<*>");
        a aVar = (a) obj2;
        a aVar2 = (a) obj;
        String str = aVar2.a;
        if (str == null) {
            str = aVar.a;
        }
        InterfaceC4938g interfaceC4938g = aVar2.b;
        if (interfaceC4938g == null) {
            interfaceC4938g = aVar.b;
        }
        linkedHashMap.put(uVar, new a(str, interfaceC4938g));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof k)) {
            return false;
        }
        k kVar = (k) obj;
        return Intrinsics.b(this.a, kVar.a) && this.b == kVar.b && this.c == kVar.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.g(this.a.hashCode() * 31, 31, this.b);
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        return this.a.entrySet().iterator();
    }

    public final String toString() {
        String str;
        StringBuilder sb = new StringBuilder();
        if (this.b) {
            sb.append("mergeDescendants=true");
            str = ", ";
        } else {
            str = "";
        }
        if (this.c) {
            sb.append(str);
            sb.append("isClearingSemantics=true");
            str = ", ";
        }
        for (Map.Entry entry : this.a.entrySet()) {
            u uVar = (u) entry.getKey();
            Object value = entry.getValue();
            sb.append(str);
            sb.append(uVar.a);
            sb.append(" : ");
            sb.append(value);
            str = ", ";
        }
        return N.F(this) + "{ " + ((Object) sb) + " }";
    }
}
