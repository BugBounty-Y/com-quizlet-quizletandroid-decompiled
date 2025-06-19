package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap;

import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class a implements Map.Entry, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ a(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // java.util.Map.Entry
    public final boolean equals(Object obj) {
        switch (this.a) {
            case 0:
                Map.Entry entry = obj instanceof Map.Entry ? (Map.Entry) obj : null;
                if (entry == null || !Intrinsics.b(entry.getKey(), this.b) || !Intrinsics.b(entry.getValue(), getValue())) {
                }
                break;
            default:
                Map.Entry entry2 = obj instanceof Map.Entry ? (Map.Entry) obj : null;
                if (entry2 == null || !Intrinsics.b(entry2.getKey(), this.b) || !Intrinsics.b(entry2.getValue(), getValue())) {
                }
                break;
        }
        return false;
    }

    @Override // java.util.Map.Entry
    public final Object getKey() {
        switch (this.a) {
        }
        return this.b;
    }

    @Override // java.util.Map.Entry
    public Object getValue() {
        switch (this.a) {
        }
        return this.c;
    }

    @Override // java.util.Map.Entry
    public final int hashCode() {
        switch (this.a) {
            case 0:
                Object obj = this.b;
                int iHashCode = obj != null ? obj.hashCode() : 0;
                Object value = getValue();
                return (value != null ? value.hashCode() : 0) ^ iHashCode;
            default:
                Object obj2 = this.b;
                int iHashCode2 = obj2 != null ? obj2.hashCode() : 0;
                Object value2 = getValue();
                return (value2 != null ? value2.hashCode() : 0) ^ iHashCode2;
        }
    }

    @Override // java.util.Map.Entry
    public Object setValue(Object obj) {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            default:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    public final String toString() {
        switch (this.a) {
            case 0:
                StringBuilder sb = new StringBuilder();
                sb.append(this.b);
                sb.append('=');
                sb.append(getValue());
                return sb.toString();
            default:
                StringBuilder sb2 = new StringBuilder();
                sb2.append(this.b);
                sb2.append('=');
                sb2.append(getValue());
                return sb2.toString();
        }
    }
}
