package androidx.compose.runtime.snapshots;

import java.util.ConcurrentModificationException;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class x implements Map.Entry, kotlin.jvm.internal.markers.d {
    public final Object a;
    public Object b;
    public final /* synthetic */ y c;

    public x(y yVar) {
        this.c = yVar;
        Map.Entry entry = yVar.d;
        Intrinsics.d(entry);
        this.a = entry.getKey();
        Map.Entry entry2 = yVar.d;
        Intrinsics.d(entry2);
        this.b = entry2.getValue();
    }

    @Override // java.util.Map.Entry
    public final Object getKey() {
        return this.a;
    }

    @Override // java.util.Map.Entry
    public final Object getValue() {
        return this.b;
    }

    @Override // java.util.Map.Entry
    public final Object setValue(Object obj) {
        y yVar = this.c;
        if (yVar.a.e().d != yVar.c) {
            throw new ConcurrentModificationException();
        }
        Object obj2 = this.b;
        yVar.a.put(this.a, obj);
        this.b = obj;
        return obj2;
    }
}
