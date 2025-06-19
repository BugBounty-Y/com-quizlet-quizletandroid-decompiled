package com.google.gson;

import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class l extends m implements Iterable {
    public final ArrayList a = new ArrayList();

    @Override // com.google.gson.m
    public final long a() {
        ArrayList arrayList = this.a;
        if (arrayList.size() == 1) {
            return ((m) arrayList.get(0)).a();
        }
        throw new IllegalStateException();
    }

    @Override // com.google.gson.m
    public final String b() {
        ArrayList arrayList = this.a;
        if (arrayList.size() == 1) {
            return ((m) arrayList.get(0)).b();
        }
        throw new IllegalStateException();
    }

    public final boolean equals(Object obj) {
        if (obj != this) {
            return (obj instanceof l) && ((l) obj).a.equals(this.a);
        }
        return true;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        return this.a.iterator();
    }
}
