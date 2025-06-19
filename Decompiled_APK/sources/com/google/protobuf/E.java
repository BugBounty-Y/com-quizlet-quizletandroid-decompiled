package com.google.protobuf;

import java.nio.charset.Charset;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.RandomAccess;

/* loaded from: classes2.dex */
public final class E extends AbstractC4006b implements F, RandomAccess {
    public final List b;

    static {
        new E();
    }

    public E(ArrayList arrayList) {
        super(true);
        this.b = arrayList;
    }

    @Override // com.google.protobuf.F
    public final F D() {
        return this.a ? new o0(this) : this;
    }

    @Override // com.google.protobuf.F
    public final Object P(int i) {
        return this.b.get(i);
    }

    @Override // java.util.AbstractList, java.util.List
    public final void add(int i, Object obj) {
        a();
        this.b.add(i, (String) obj);
        ((AbstractList) this).modCount++;
    }

    @Override // com.google.protobuf.AbstractC4006b, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean addAll(Collection collection) {
        return addAll(this.b.size(), collection);
    }

    @Override // com.google.protobuf.AbstractC4006b, java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final void clear() {
        a();
        this.b.clear();
        ((AbstractList) this).modCount++;
    }

    @Override // java.util.AbstractList, java.util.List
    public final Object get(int i) {
        String str;
        List list = this.b;
        Object obj = list.get(i);
        if (obj instanceof String) {
            return (String) obj;
        }
        if (!(obj instanceof C4012f)) {
            byte[] bArr = (byte[]) obj;
            String str2 = new String(bArr, C.a);
            h0 h0Var = w0.a;
            if (w0.a.e(0, bArr, bArr.length) == 0) {
                list.set(i, str2);
            }
            return str2;
        }
        C4012f c4012f = (C4012f) obj;
        c4012f.getClass();
        Charset charset = C.a;
        if (c4012f.size() == 0) {
            str = "";
        } else {
            str = new String(c4012f.b, c4012f.e(), c4012f.size(), charset);
        }
        int iE = c4012f.e();
        if (w0.a.e(iE, c4012f.b, c4012f.size() + iE) == 0) {
            list.set(i, str);
        }
        return str;
    }

    @Override // com.google.protobuf.F
    public final List l() {
        return Collections.unmodifiableList(this.b);
    }

    @Override // com.google.protobuf.F
    public final void p(C4012f c4012f) {
        a();
        this.b.add(c4012f);
        ((AbstractList) this).modCount++;
    }

    @Override // com.google.protobuf.B
    public final B q(int i) {
        List list = this.b;
        if (i < list.size()) {
            throw new IllegalArgumentException();
        }
        ArrayList arrayList = new ArrayList(i);
        arrayList.addAll(list);
        return new E(arrayList);
    }

    @Override // com.google.protobuf.AbstractC4006b, java.util.AbstractList, java.util.List
    public final Object remove(int i) {
        a();
        Object objRemove = this.b.remove(i);
        ((AbstractList) this).modCount++;
        if (objRemove instanceof String) {
            return (String) objRemove;
        }
        if (!(objRemove instanceof C4012f)) {
            return new String((byte[]) objRemove, C.a);
        }
        C4012f c4012f = (C4012f) objRemove;
        c4012f.getClass();
        Charset charset = C.a;
        if (c4012f.size() == 0) {
            return "";
        }
        return new String(c4012f.b, c4012f.e(), c4012f.size(), charset);
    }

    @Override // java.util.AbstractList, java.util.List
    public final Object set(int i, Object obj) {
        a();
        Object obj2 = this.b.set(i, (String) obj);
        if (obj2 instanceof String) {
            return (String) obj2;
        }
        if (!(obj2 instanceof C4012f)) {
            return new String((byte[]) obj2, C.a);
        }
        C4012f c4012f = (C4012f) obj2;
        c4012f.getClass();
        Charset charset = C.a;
        if (c4012f.size() == 0) {
            return "";
        }
        return new String(c4012f.b, c4012f.e(), c4012f.size(), charset);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.b.size();
    }

    public E() {
        super(false);
        this.b = Collections.EMPTY_LIST;
    }

    @Override // com.google.protobuf.AbstractC4006b, java.util.AbstractList, java.util.List
    public final boolean addAll(int i, Collection collection) {
        a();
        if (collection instanceof F) {
            collection = ((F) collection).l();
        }
        boolean zAddAll = this.b.addAll(i, collection);
        ((AbstractList) this).modCount++;
        return zAddAll;
    }

    public E(int i) {
        this(new ArrayList(i));
    }
}
