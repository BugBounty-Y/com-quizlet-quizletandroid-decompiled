package com.iabtcf.utils;

import java.util.Iterator;

/* loaded from: classes2.dex */
public abstract class n implements Iterable {
    @Override // java.lang.Iterable
    public final Iterator iterator() {
        return new m(this);
    }
}
