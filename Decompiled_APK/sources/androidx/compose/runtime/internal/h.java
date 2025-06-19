package androidx.compose.runtime.internal;

import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.Z0;
import androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.n;

/* loaded from: classes.dex */
public final class h extends androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.e {
    public i g;

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.e, java.util.AbstractMap, java.util.Map
    public final /* bridge */ boolean containsKey(Object obj) {
        if (obj instanceof AbstractC0809m0) {
            return super.containsKey((AbstractC0809m0) obj);
        }
        return false;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final /* bridge */ boolean containsValue(Object obj) {
        if (obj instanceof Z0) {
            return super.containsValue((Z0) obj);
        }
        return false;
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.e, java.util.AbstractMap, java.util.Map
    public final /* bridge */ Object get(Object obj) {
        if (obj instanceof AbstractC0809m0) {
            return (Z0) super.get((AbstractC0809m0) obj);
        }
        return null;
    }

    @Override // java.util.Map
    public final /* bridge */ Object getOrDefault(Object obj, Object obj2) {
        return !(obj instanceof AbstractC0809m0) ? obj2 : (Z0) super.getOrDefault((AbstractC0809m0) obj, (Z0) obj2);
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.e
    /* renamed from: h, reason: merged with bridge method [inline-methods] */
    public final i build() {
        n nVar = this.c;
        i iVar = this.g;
        if (nVar != iVar.b) {
            this.b = new androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b();
            iVar = new i(this.c, d());
        }
        this.g = iVar;
        return iVar;
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.e, java.util.AbstractMap, java.util.Map
    public final /* bridge */ Object remove(Object obj) {
        if (obj instanceof AbstractC0809m0) {
            return (Z0) super.remove((AbstractC0809m0) obj);
        }
        return null;
    }
}
