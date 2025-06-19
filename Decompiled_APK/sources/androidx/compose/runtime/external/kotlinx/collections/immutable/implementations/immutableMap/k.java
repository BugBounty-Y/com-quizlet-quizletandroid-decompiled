package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap;

import java.util.Iterator;
import java.util.Map;
import kotlin.collections.AbstractC4925p;

/* loaded from: classes.dex */
public final class k extends AbstractC4925p implements androidx.compose.runtime.external.kotlinx.collections.immutable.b {
    public final /* synthetic */ int b;
    public final c c;

    public /* synthetic */ k(c cVar, int i) {
        this.b = i;
        this.c = cVar;
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        switch (this.b) {
        }
        return this.c.d();
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection, java.util.List
    public final boolean contains(Object obj) {
        Map.Entry entry;
        switch (this.b) {
            case 0:
                if (!(obj instanceof Map.Entry) || (entry = (Map.Entry) obj) == null) {
                    return false;
                }
                Object key = entry.getKey();
                c cVar = this.c;
                Object obj2 = cVar.get(key);
                return obj2 != null ? obj2.equals(entry.getValue()) : entry.getValue() == null && cVar.containsKey(entry.getKey());
            default:
                return this.c.containsKey(obj);
        }
    }

    @Override // kotlin.collections.AbstractC4925p, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        switch (this.b) {
            case 0:
                n nVar = this.c.b;
                o[] oVarArr = new o[8];
                for (int i = 0; i < 8; i++) {
                    oVarArr[i] = new p(0);
                }
                return new l(nVar, oVarArr);
            default:
                n nVar2 = this.c.b;
                o[] oVarArr2 = new o[8];
                for (int i2 = 0; i2 < 8; i2++) {
                    oVarArr2[i2] = new p(1);
                }
                return new l(nVar2, oVarArr2);
        }
    }
}
