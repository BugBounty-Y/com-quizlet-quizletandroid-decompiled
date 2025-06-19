package com.google.common.cache;

import java.util.AbstractQueue;
import java.util.Iterator;

/* renamed from: com.google.common.cache.h, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3914h extends AbstractQueue {
    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable
    public final Iterator iterator() {
        return com.google.common.collect.D.j.j();
    }

    @Override // java.util.Queue
    public final boolean offer(Object obj) {
        return true;
    }

    @Override // java.util.Queue
    public final Object peek() {
        return null;
    }

    @Override // java.util.Queue
    public final Object poll() {
        return null;
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final int size() {
        return 0;
    }
}
