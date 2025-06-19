package com.sdk.growthbook.model;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.markers.a;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBJson extends GBValue implements Map<String, GBValue>, a {

    @NotNull
    private final Map<String, GBValue> value;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public GBJson(@NotNull Map<String, ? extends GBValue> value) {
        super(null);
        Intrinsics.checkNotNullParameter(value, "value");
        this.value = value;
    }

    private final Map<String, GBValue> component1() {
        return this.value;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ GBJson copy$default(GBJson gBJson, Map map, int i, Object obj) {
        if ((i & 1) != 0) {
            map = gBJson.value;
        }
        return gBJson.copy(map);
    }

    @Override // java.util.Map
    public void clear() {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    /* renamed from: compute, reason: avoid collision after fix types in other method */
    public GBValue compute2(String str, BiFunction<? super String, ? super GBValue, ? extends GBValue> biFunction) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    /* renamed from: computeIfAbsent, reason: avoid collision after fix types in other method */
    public GBValue computeIfAbsent2(String str, Function<? super String, ? extends GBValue> function) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    /* renamed from: computeIfPresent, reason: avoid collision after fix types in other method */
    public GBValue computeIfPresent2(String str, BiFunction<? super String, ? super GBValue, ? extends GBValue> biFunction) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    public boolean containsKey(@NotNull String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        return this.value.containsKey(key);
    }

    public boolean containsValue(@NotNull GBValue value) {
        Intrinsics.checkNotNullParameter(value, "value");
        return this.value.containsValue(value);
    }

    @NotNull
    public final GBJson copy(@NotNull Map<String, ? extends GBValue> value) {
        Intrinsics.checkNotNullParameter(value, "value");
        return new GBJson(value);
    }

    @Override // java.util.Map
    public final /* bridge */ Set<Map.Entry<String, GBValue>> entrySet() {
        return getEntries();
    }

    @Override // java.util.Map
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof GBJson) && Intrinsics.b(this.value, ((GBJson) obj).value);
    }

    public GBValue get(@NotNull String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        return this.value.get(key);
    }

    @NotNull
    public Set<Map.Entry<String, GBValue>> getEntries() {
        return this.value.entrySet();
    }

    @NotNull
    public Set<String> getKeys() {
        return this.value.keySet();
    }

    public int getSize() {
        return this.value.size();
    }

    @NotNull
    public Collection<GBValue> getValues() {
        return this.value.values();
    }

    @Override // java.util.Map
    public int hashCode() {
        return this.value.hashCode();
    }

    @Override // java.util.Map
    public boolean isEmpty() {
        return this.value.isEmpty();
    }

    @Override // java.util.Map
    public final /* bridge */ Set<String> keySet() {
        return getKeys();
    }

    /* renamed from: merge, reason: avoid collision after fix types in other method */
    public GBValue merge2(String str, GBValue gBValue, BiFunction<? super GBValue, ? super GBValue, ? extends GBValue> biFunction) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    /* renamed from: put, reason: avoid collision after fix types in other method */
    public GBValue put2(String str, GBValue gBValue) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Map
    public void putAll(Map<? extends String, ? extends GBValue> map) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    /* renamed from: putIfAbsent, reason: avoid collision after fix types in other method */
    public GBValue putIfAbsent2(String str, GBValue gBValue) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // java.util.Map
    public GBValue remove(Object obj) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    /* renamed from: replace, reason: avoid collision after fix types in other method */
    public GBValue replace2(String str, GBValue gBValue) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Map
    public void replaceAll(BiFunction<? super String, ? super GBValue, ? extends GBValue> biFunction) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Map
    public final /* bridge */ int size() {
        return getSize();
    }

    @NotNull
    public String toString() {
        return "GBJson(value=" + this.value + ')';
    }

    @Override // java.util.Map
    public final /* bridge */ Collection<GBValue> values() {
        return getValues();
    }

    @Override // java.util.Map
    public /* bridge */ /* synthetic */ GBValue compute(String str, BiFunction<? super String, ? super GBValue, ? extends GBValue> biFunction) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Map
    public /* bridge */ /* synthetic */ GBValue computeIfAbsent(String str, Function<? super String, ? extends GBValue> function) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Map
    public /* bridge */ /* synthetic */ GBValue computeIfPresent(String str, BiFunction<? super String, ? super GBValue, ? extends GBValue> biFunction) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Map
    public final /* bridge */ boolean containsKey(Object obj) {
        if (obj instanceof String) {
            return containsKey((String) obj);
        }
        return false;
    }

    @Override // java.util.Map
    public final /* bridge */ boolean containsValue(Object obj) {
        if (obj instanceof GBValue) {
            return containsValue((GBValue) obj);
        }
        return false;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // java.util.Map
    public final /* bridge */ GBValue get(Object obj) {
        if (obj instanceof String) {
            return get((String) obj);
        }
        return null;
    }

    @Override // java.util.Map
    public /* bridge */ /* synthetic */ GBValue merge(String str, GBValue gBValue, BiFunction<? super GBValue, ? super GBValue, ? extends GBValue> biFunction) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Map
    public /* bridge */ /* synthetic */ GBValue put(String str, GBValue gBValue) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Map
    public /* bridge */ /* synthetic */ GBValue putIfAbsent(String str, GBValue gBValue) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Map
    public boolean remove(Object obj, Object obj2) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Map
    public /* bridge */ /* synthetic */ GBValue replace(String str, GBValue gBValue) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Map
    public final /* bridge */ /* synthetic */ GBValue get(Object obj) {
        if (obj instanceof String) {
            return get((String) obj);
        }
        return null;
    }

    @Override // java.util.Map
    public /* bridge */ /* synthetic */ boolean replace(String str, GBValue gBValue, GBValue gBValue2) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    /* renamed from: replace, reason: avoid collision after fix types in other method */
    public boolean replace2(String str, GBValue gBValue, GBValue gBValue2) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }
}
