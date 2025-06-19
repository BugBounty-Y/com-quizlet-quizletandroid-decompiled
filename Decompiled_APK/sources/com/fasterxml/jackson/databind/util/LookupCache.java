package com.fasterxml.jackson.databind.util;

import java.util.function.BiConsumer;

/* loaded from: classes.dex */
public interface LookupCache<K, V> {
    void contents(BiConsumer<K, V> biConsumer);

    V get(Object obj);

    V put(K k, V v);

    V putIfAbsent(K k, V v);

    int size();
}
