package com.google.android.gms.internal.ads;

import java.util.ArrayList;
import java.util.Iterator;

/* renamed from: com.google.android.gms.internal.ads.wC, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2778wC implements Iterator {
    public final /* synthetic */ int a;
    public int b = 0;
    public final /* synthetic */ Iterable c;

    public /* synthetic */ C2778wC(Iterable iterable, int i) {
        this.a = i;
        this.c = iterable;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        org.jsoup.nodes.b bVar;
        switch (this.a) {
            case 0:
                int i = this.b;
                C2821xC c2821xC = (C2821xC) this.c;
                return i < c2821xC.a.size() || c2821xC.b.hasNext();
        }
        while (true) {
            int i2 = this.b;
            bVar = (org.jsoup.nodes.b) this.c;
            if (i2 < bVar.a && org.jsoup.nodes.b.r(bVar.b[i2])) {
                this.b++;
            }
        }
        return this.b < bVar.a;
    }

    @Override // java.util.Iterator
    public final Object next() {
        switch (this.a) {
            case 0:
                int i = this.b;
                C2821xC c2821xC = (C2821xC) this.c;
                ArrayList arrayList = c2821xC.a;
                if (i >= arrayList.size()) {
                    arrayList.add(c2821xC.b.next());
                    return next();
                }
                int i2 = this.b;
                this.b = i2 + 1;
                return arrayList.get(i2);
            default:
                org.jsoup.nodes.b bVar = (org.jsoup.nodes.b) this.c;
                String[] strArr = bVar.b;
                int i3 = this.b;
                org.jsoup.nodes.a aVar = new org.jsoup.nodes.a(strArr[i3], (String) bVar.c[i3], bVar);
                this.b++;
                return aVar;
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException();
            default:
                int i = this.b - 1;
                this.b = i;
                ((org.jsoup.nodes.b) this.c).u(i);
                return;
        }
    }
}
