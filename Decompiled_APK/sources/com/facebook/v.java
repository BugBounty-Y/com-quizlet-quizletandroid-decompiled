package com.facebook;

import android.os.Handler;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class v extends AbstractList {
    public static final AtomicInteger e = new AtomicInteger();
    public Handler a;
    public final String b;
    public final ArrayList c;
    public final ArrayList d;

    public v(List requests) {
        Intrinsics.checkNotNullParameter(requests, "requests");
        this.b = String.valueOf(Integer.valueOf(e.incrementAndGet()));
        this.d = new ArrayList();
        this.c = new ArrayList(requests);
    }

    @Override // java.util.AbstractList, java.util.List
    public final void add(int i, Object obj) {
        t element = (t) obj;
        Intrinsics.checkNotNullParameter(element, "element");
        this.c.add(i, element);
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final void clear() {
        this.c.clear();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final /* bridge */ boolean contains(Object obj) {
        if (obj == null ? true : obj instanceof t) {
            return super.contains((t) obj);
        }
        return false;
    }

    @Override // java.util.AbstractList, java.util.List
    public final Object get(int i) {
        return (t) this.c.get(i);
    }

    @Override // java.util.AbstractList, java.util.List
    public final /* bridge */ int indexOf(Object obj) {
        if (obj == null ? true : obj instanceof t) {
            return super.indexOf((t) obj);
        }
        return -1;
    }

    @Override // java.util.AbstractList, java.util.List
    public final /* bridge */ int lastIndexOf(Object obj) {
        if (obj == null ? true : obj instanceof t) {
            return super.lastIndexOf((t) obj);
        }
        return -1;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final /* bridge */ boolean remove(Object obj) {
        if (obj == null ? true : obj instanceof t) {
            return super.remove((t) obj);
        }
        return false;
    }

    @Override // java.util.AbstractList, java.util.List
    public final Object set(int i, Object obj) {
        t element = (t) obj;
        Intrinsics.checkNotNullParameter(element, "element");
        return (t) this.c.set(i, element);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.c.size();
    }

    @Override // java.util.AbstractList, java.util.List
    public final Object remove(int i) {
        return (t) this.c.remove(i);
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean add(Object obj) {
        t element = (t) obj;
        Intrinsics.checkNotNullParameter(element, "element");
        return this.c.add(element);
    }

    public v(t... requests) {
        Intrinsics.checkNotNullParameter(requests, "requests");
        this.b = String.valueOf(Integer.valueOf(e.incrementAndGet()));
        this.d = new ArrayList();
        this.c = new ArrayList(C4930v.c(requests));
    }
}
