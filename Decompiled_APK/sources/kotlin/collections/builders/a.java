package kotlin.collections.builders;

import java.util.Map;
import kotlin.collections.AbstractC4923n;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class a extends AbstractC4923n {
    public abstract boolean b(Map.Entry entry);

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        if (!(obj instanceof Map.Entry)) {
            return false;
        }
        Map.Entry element = (Map.Entry) obj;
        Intrinsics.checkNotNullParameter(element, "element");
        return b(element);
    }

    public /* bridge */ boolean e(Map.Entry entry) {
        return super.remove(entry);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final /* bridge */ boolean remove(Object obj) {
        if (obj instanceof Map.Entry) {
            return e((Map.Entry) obj);
        }
        return false;
    }
}
