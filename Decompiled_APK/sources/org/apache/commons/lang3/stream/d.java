package org.apache.commons.lang3.stream;

import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;

/* loaded from: classes3.dex */
public final class d implements Collector {
    public final b a;
    public final Set b;
    public final c c;
    public final com.fasterxml.jackson.databind.introspect.a d;
    public final a e;

    public d(a aVar, b bVar, c cVar, com.fasterxml.jackson.databind.introspect.a aVar2, Set set) {
        this.e = aVar;
        this.a = bVar;
        this.c = cVar;
        this.d = aVar2;
        this.b = set;
    }

    @Override // java.util.stream.Collector
    public final BiConsumer accumulator() {
        return this.a;
    }

    @Override // java.util.stream.Collector
    public final Set characteristics() {
        return this.b;
    }

    @Override // java.util.stream.Collector
    public final BinaryOperator combiner() {
        return this.c;
    }

    @Override // java.util.stream.Collector
    public final Function finisher() {
        return this.d;
    }

    @Override // java.util.stream.Collector
    public final Supplier supplier() {
        return this.e;
    }
}
