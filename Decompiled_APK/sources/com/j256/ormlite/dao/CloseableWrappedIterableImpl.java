package com.j256.ormlite.dao;

import android.content.res.TypedArray;
import android.media.MediaDrm;
import android.media.MediaMetadataRetriever;
import com.j256.ormlite.misc.IOUtils;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public class CloseableWrappedIterableImpl<T> implements CloseableWrappedIterable<T> {
    private final CloseableIterable<T> iterable;
    private CloseableIterator<T> iterator;

    public CloseableWrappedIterableImpl(CloseableIterable<T> closeableIterable) {
        this.iterable = closeableIterable;
    }

    @Override // com.j256.ormlite.dao.CloseableWrappedIterable, java.lang.AutoCloseable
    public void close() throws Exception {
        boolean zIsTerminated;
        CloseableIterator<T> closeableIterator = this.iterator;
        if (closeableIterator != null) {
            if (closeableIterator instanceof AutoCloseable) {
                closeableIterator.close();
            } else if (closeableIterator instanceof ExecutorService) {
                ExecutorService executorService = (ExecutorService) closeableIterator;
                if (executorService != ForkJoinPool.commonPool() && !(zIsTerminated = executorService.isTerminated())) {
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
            } else if (closeableIterator instanceof TypedArray) {
                ((TypedArray) closeableIterator).recycle();
            } else if (closeableIterator instanceof MediaMetadataRetriever) {
                ((MediaMetadataRetriever) closeableIterator).release();
            } else {
                if (!(closeableIterator instanceof MediaDrm)) {
                    throw new IllegalArgumentException();
                }
                ((MediaDrm) closeableIterator).release();
            }
            this.iterator = null;
        }
    }

    @Override // com.j256.ormlite.dao.CloseableWrappedIterable, com.j256.ormlite.dao.CloseableIterable
    public CloseableIterator<T> closeableIterator() {
        IOUtils.closeQuietly(this);
        CloseableIterator<T> closeableIterator = this.iterable.closeableIterator();
        this.iterator = closeableIterator;
        return closeableIterator;
    }

    @Override // java.lang.Iterable
    public CloseableIterator<T> iterator() {
        return closeableIterator();
    }
}
