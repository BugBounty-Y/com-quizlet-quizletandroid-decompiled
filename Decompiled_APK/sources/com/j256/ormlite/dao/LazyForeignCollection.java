package com.j256.ormlite.dao;

import android.content.res.TypedArray;
import android.media.MediaDrm;
import android.media.MediaMetadataRetriever;
import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.misc.IOUtils;
import java.io.Serializable;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public class LazyForeignCollection<T, ID> extends BaseForeignCollection<T, ID> implements Serializable {
    private static final long serialVersionUID = -5460708106909626233L;
    private transient CloseableIterator<T> lastIterator;

    public LazyForeignCollection(Dao<T, ID> dao, Object obj, Object obj2, FieldType fieldType, String str, boolean z) {
        super(dao, obj, obj2, fieldType, str, z);
    }

    @Override // com.j256.ormlite.dao.BaseForeignCollection, com.j256.ormlite.dao.ForeignCollection
    public void closeLastIterator() throws Exception {
        boolean zIsTerminated;
        CloseableIterator<T> closeableIterator = this.lastIterator;
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
            this.lastIterator = null;
        }
    }

    @Override // com.j256.ormlite.dao.BaseForeignCollection, com.j256.ormlite.dao.ForeignCollection, com.j256.ormlite.dao.CloseableIterable
    public CloseableIterator<T> closeableIterator() {
        return closeableIterator(-1);
    }

    @Override // java.util.Collection
    public boolean contains(Object obj) {
        CloseableIterator<T> it2 = iterator();
        while (it2.hasNext()) {
            try {
                if (it2.next().equals(obj)) {
                    IOUtils.closeQuietly(it2);
                    return true;
                }
            } catch (Throwable th) {
                IOUtils.closeQuietly(it2);
                throw th;
            }
        }
        IOUtils.closeQuietly(it2);
        return false;
    }

    @Override // java.util.Collection
    public boolean containsAll(Collection<?> collection) {
        HashSet hashSet = new HashSet(collection);
        CloseableIterator<T> it2 = iterator();
        while (it2.hasNext()) {
            try {
                hashSet.remove(it2.next());
            } catch (Throwable th) {
                IOUtils.closeQuietly(it2);
                throw th;
            }
        }
        boolean zIsEmpty = hashSet.isEmpty();
        IOUtils.closeQuietly(it2);
        return zIsEmpty;
    }

    @Override // java.util.Collection
    public boolean equals(Object obj) {
        return super.equals(obj);
    }

    @Override // com.j256.ormlite.dao.BaseForeignCollection, com.j256.ormlite.dao.ForeignCollection
    public CloseableWrappedIterable<T> getWrappedIterable() {
        return getWrappedIterable(-1);
    }

    @Override // java.util.Collection
    public int hashCode() {
        return super.hashCode();
    }

    @Override // com.j256.ormlite.dao.BaseForeignCollection, com.j256.ormlite.dao.ForeignCollection
    public boolean isEager() {
        return false;
    }

    @Override // java.util.Collection
    public boolean isEmpty() {
        CloseableIterator<T> it2 = iterator();
        try {
            return !it2.hasNext();
        } finally {
            IOUtils.closeQuietly(it2);
        }
    }

    @Override // com.j256.ormlite.dao.BaseForeignCollection, com.j256.ormlite.dao.ForeignCollection
    public CloseableIterator<T> iteratorThrow() throws SQLException {
        return iteratorThrow(-1);
    }

    @Override // com.j256.ormlite.dao.BaseForeignCollection, com.j256.ormlite.dao.ForeignCollection
    public int refreshAll() {
        throw new UnsupportedOperationException("Cannot call updateAll() on a lazy collection.");
    }

    @Override // com.j256.ormlite.dao.BaseForeignCollection, com.j256.ormlite.dao.ForeignCollection
    public int refreshCollection() {
        return 0;
    }

    @Override // com.j256.ormlite.dao.BaseForeignCollection, java.util.Collection
    public boolean remove(Object obj) {
        CloseableIterator<T> it2 = iterator();
        while (it2.hasNext()) {
            try {
                if (it2.next().equals(obj)) {
                    it2.remove();
                    IOUtils.closeQuietly(it2);
                    return true;
                }
            } catch (Throwable th) {
                IOUtils.closeQuietly(it2);
                throw th;
            }
        }
        IOUtils.closeQuietly(it2);
        return false;
    }

    @Override // com.j256.ormlite.dao.BaseForeignCollection, java.util.Collection
    public boolean removeAll(Collection<?> collection) {
        CloseableIterator<T> it2 = iterator();
        boolean z = false;
        while (it2.hasNext()) {
            try {
                if (collection.contains(it2.next())) {
                    it2.remove();
                    z = true;
                }
            } finally {
                IOUtils.closeQuietly(it2);
            }
        }
        return z;
    }

    public CloseableIterator<T> seperateIteratorThrow(int i) throws SQLException {
        Dao<T, ID> dao = this.dao;
        if (dao != null) {
            return dao.iterator(getPreparedQuery(), i);
        }
        throw new IllegalStateException("Internal DAO object is null.  Maybe the collection was deserialized or otherwise constructed wrongly.  Use dao.assignEmptyForeignCollection(...) or dao.getEmptyForeignCollection(...) instead");
    }

    @Override // java.util.Collection
    public int size() {
        CloseableIterator<T> it2 = iterator();
        int i = 0;
        while (it2.hasNext()) {
            try {
                it2.moveToNext();
                i++;
            } finally {
                IOUtils.closeQuietly(it2);
            }
        }
        return i;
    }

    @Override // java.util.Collection
    public Object[] toArray() {
        return toList().toArray();
    }

    public List<T> toList() {
        ArrayList arrayList = new ArrayList();
        CloseableIterator<T> it2 = iterator();
        while (it2.hasNext()) {
            try {
                arrayList.add(it2.next());
            } finally {
                IOUtils.closeQuietly(it2);
            }
        }
        return arrayList;
    }

    @Override // com.j256.ormlite.dao.BaseForeignCollection, com.j256.ormlite.dao.ForeignCollection
    public int updateAll() {
        throw new UnsupportedOperationException("Cannot call updateAll() on a lazy collection.");
    }

    @Override // com.j256.ormlite.dao.BaseForeignCollection, com.j256.ormlite.dao.ForeignCollection
    public CloseableIterator<T> closeableIterator(int i) {
        try {
            return iteratorThrow(i);
        } catch (SQLException e) {
            throw new IllegalStateException("Could not build lazy iterator for " + this.dao.getDataClass(), e);
        }
    }

    @Override // com.j256.ormlite.dao.BaseForeignCollection, com.j256.ormlite.dao.ForeignCollection
    public CloseableWrappedIterable<T> getWrappedIterable(final int i) {
        return new CloseableWrappedIterableImpl(new CloseableIterable<T>() { // from class: com.j256.ormlite.dao.LazyForeignCollection.1
            @Override // com.j256.ormlite.dao.CloseableIterable
            public CloseableIterator<T> closeableIterator() {
                try {
                    return LazyForeignCollection.this.seperateIteratorThrow(i);
                } catch (Exception e) {
                    throw new IllegalStateException("Could not build lazy iterator for " + LazyForeignCollection.this.dao.getDataClass(), e);
                }
            }

            @Override // java.lang.Iterable
            public CloseableIterator<T> iterator() {
                return closeableIterator();
            }
        });
    }

    @Override // java.util.Collection, java.lang.Iterable
    public CloseableIterator<T> iterator() {
        return closeableIterator(-1);
    }

    @Override // com.j256.ormlite.dao.BaseForeignCollection, com.j256.ormlite.dao.ForeignCollection
    public CloseableIterator<T> iteratorThrow(int i) throws SQLException {
        CloseableIterator<T> closeableIteratorSeperateIteratorThrow = seperateIteratorThrow(i);
        this.lastIterator = closeableIteratorSeperateIteratorThrow;
        return closeableIteratorSeperateIteratorThrow;
    }

    @Override // com.j256.ormlite.dao.BaseForeignCollection, com.j256.ormlite.dao.ForeignCollection
    public CloseableIterator<T> iterator(int i) {
        return closeableIterator(i);
    }

    @Override // java.util.Collection
    public <E> E[] toArray(E[] eArr) {
        CloseableIterator<T> it2 = iterator();
        ArrayList arrayList = null;
        int i = 0;
        while (it2.hasNext()) {
            try {
                T next = it2.next();
                if (i >= eArr.length) {
                    if (arrayList == null) {
                        arrayList = new ArrayList();
                        for (E e : eArr) {
                            arrayList.add(e);
                        }
                    }
                    arrayList.add(next);
                } else {
                    eArr[i] = next;
                }
                i++;
            } catch (Throwable th) {
                IOUtils.closeQuietly(it2);
                throw th;
            }
        }
        IOUtils.closeQuietly(it2);
        if (arrayList == null) {
            if (i < eArr.length - 1) {
                eArr[i] = 0;
            }
            return eArr;
        }
        return (E[]) arrayList.toArray(eArr);
    }
}
