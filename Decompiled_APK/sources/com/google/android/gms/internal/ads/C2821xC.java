package com.google.android.gms.internal.ads;

import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.NoSuchElementException;

/* renamed from: com.google.android.gms.internal.ads.xC, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2821xC extends AbstractList {
    public static final AbstractC2457os c = AbstractC2457os.o(C2821xC.class);
    public final ArrayList a;
    public final AbstractC2692uC b;

    public C2821xC(ArrayList arrayList, AbstractC2692uC abstractC2692uC) {
        this.a = arrayList;
        this.b = abstractC2692uC;
    }

    @Override // java.util.AbstractList, java.util.List
    public final Object get(int i) {
        ArrayList arrayList = this.a;
        if (arrayList.size() > i) {
            return arrayList.get(i);
        }
        AbstractC2692uC abstractC2692uC = this.b;
        if (!abstractC2692uC.hasNext()) {
            throw new NoSuchElementException();
        }
        arrayList.add(abstractC2692uC.next());
        return get(i);
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.List
    public final Iterator iterator() {
        return new C2778wC(this, 0);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        AbstractC2457os abstractC2457os = c;
        abstractC2457os.i("potentially expensive size() call");
        abstractC2457os.i("blowup running");
        while (true) {
            AbstractC2692uC abstractC2692uC = this.b;
            boolean zHasNext = abstractC2692uC.hasNext();
            ArrayList arrayList = this.a;
            if (!zHasNext) {
                return arrayList.size();
            }
            arrayList.add(abstractC2692uC.next());
        }
    }
}
