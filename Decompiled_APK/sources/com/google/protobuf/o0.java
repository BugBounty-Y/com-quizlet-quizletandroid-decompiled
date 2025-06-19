package com.google.protobuf;

import java.util.AbstractList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.RandomAccess;

/* loaded from: classes2.dex */
public final class o0 extends AbstractList implements F, RandomAccess {
    public final E a;

    public o0(E e) {
        this.a = e;
    }

    @Override // com.google.protobuf.F
    public final F D() {
        return this;
    }

    @Override // com.google.protobuf.F
    public final Object P(int i) {
        return this.a.b.get(i);
    }

    @Override // java.util.AbstractList, java.util.List
    public final Object get(int i) {
        return (String) this.a.get(i);
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.List
    public final Iterator iterator() {
        n0 n0Var = new n0();
        n0Var.a = this.a.iterator();
        return n0Var;
    }

    @Override // com.google.protobuf.F
    public final List l() {
        return Collections.unmodifiableList(this.a.b);
    }

    @Override // java.util.AbstractList, java.util.List
    public final ListIterator listIterator(int i) {
        m0 m0Var = new m0();
        m0Var.a = this.a.listIterator(i);
        return m0Var;
    }

    @Override // com.google.protobuf.F
    public final void p(C4012f c4012f) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.a.b.size();
    }
}
