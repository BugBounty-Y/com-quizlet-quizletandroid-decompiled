package com.j256.ormlite.dao;

import java.util.Spliterator;

/* loaded from: classes2.dex */
public interface CloseableSpliterator<T> extends Spliterator<T>, AutoCloseable {
    void closeQuietly();
}
