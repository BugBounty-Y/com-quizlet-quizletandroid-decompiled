package androidx.compose.runtime.internal;

import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.Z0;
import androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.n;

/* loaded from: classes.dex */
public final class i extends androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.c implements InterfaceC0803j0 {
    public static final i e = new i(n.e, 0);

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.c, androidx.compose.runtime.external.kotlinx.collections.immutable.e
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.d builder() {
        h hVar = new h(this);
        hVar.g = this;
        return hVar;
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.c, kotlin.collections.AbstractC4919j, java.util.Map
    public final /* bridge */ boolean containsKey(Object obj) {
        if (obj instanceof AbstractC0809m0) {
            return super.containsKey((AbstractC0809m0) obj);
        }
        return false;
    }

    @Override // kotlin.collections.AbstractC4919j, java.util.Map
    public final /* bridge */ boolean containsValue(Object obj) {
        if (obj instanceof Z0) {
            return super.containsValue((Z0) obj);
        }
        return false;
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.c
    /* renamed from: g */
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.e builder() {
        h hVar = new h(this);
        hVar.g = this;
        return hVar;
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.c, kotlin.collections.AbstractC4919j, java.util.Map
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
}
