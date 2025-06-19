package com.j256.ormlite.dao;

import android.content.res.TypedArray;
import android.media.MediaDrm;
import android.media.MediaMetadataRetriever;
import com.j256.ormlite.misc.IOUtils;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/* loaded from: classes2.dex */
public class CloseableSpliteratorImpl<T> implements CloseableSpliterator<T> {
    private final Spliterator<T> delegate;
    private final CloseableIterator<? extends T> iterator;

    public CloseableSpliteratorImpl(CloseableIterator<? extends T> closeableIterator) {
        this.delegate = Spliterators.spliteratorUnknownSize(closeableIterator, 0);
        this.iterator = closeableIterator;
    }

    @Override // java.util.Spliterator
    public int characteristics() {
        return this.delegate.characteristics();
    }

    @Override // java.lang.AutoCloseable
    public void close() throws Exception {
        boolean zIsTerminated;
        CloseableIterator<? extends T> closeableIterator = this.iterator;
        if (closeableIterator instanceof AutoCloseable) {
            closeableIterator.close();
            return;
        }
        if (!(closeableIterator instanceof ExecutorService)) {
            if (closeableIterator instanceof TypedArray) {
                ((TypedArray) closeableIterator).recycle();
                return;
            } else if (closeableIterator instanceof MediaMetadataRetriever) {
                ((MediaMetadataRetriever) closeableIterator).release();
                return;
            } else {
                if (!(closeableIterator instanceof MediaDrm)) {
                    throw new IllegalArgumentException();
                }
                ((MediaDrm) closeableIterator).release();
                return;
            }
        }
        ExecutorService executorService = (ExecutorService) closeableIterator;
        if (executorService == ForkJoinPool.commonPool() || (zIsTerminated = executorService.isTerminated())) {
            return;
        }
        executorService.shutdown();
        boolean z = false;
        while (!zIsTerminated) {
            try {
                zIsTerminated = executorService.awaitTermination(1L, TimeUnit.DAYS);
            } catch (InterruptedException unused) {
                if (!z) {
                    executorService.shutdownNow();
                    z = true;
                }
            }
        }
        if (z) {
            Thread.currentThread().interrupt();
        }
    }

    @Override // com.j256.ormlite.dao.CloseableSpliterator
    public void closeQuietly() {
        IOUtils.closeQuietly(this);
    }

    @Override // java.util.Spliterator
    public long estimateSize() {
        return this.delegate.estimateSize();
    }

    @Override // java.util.Spliterator
    public boolean tryAdvance(Consumer<? super T> consumer) {
        return this.delegate.tryAdvance(consumer);
    }

    @Override // java.util.Spliterator
    public Spliterator<T> trySplit() {
        return this.delegate.trySplit();
    }
}
