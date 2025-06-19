package com.bumptech.glide.load.engine;

import com.google.common.collect.C3922e;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class n implements Iterable {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ n(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        switch (this.a) {
            case 0:
                return ((ArrayList) this.b).iterator();
            default:
                Iterable[] iterableArr = (Iterable[]) this.b;
                C3922e c3922e = new C3922e(iterableArr.length, iterableArr);
                com.google.common.collect.s sVar = new com.google.common.collect.s();
                sVar.b = com.google.common.collect.r.e;
                sVar.c = c3922e;
                return sVar;
        }
    }

    public String toString() {
        switch (this.a) {
            case 1:
                Iterator it2 = iterator();
                StringBuilder sb = new StringBuilder("[");
                boolean z = true;
                while (true) {
                    com.google.common.collect.s sVar = (com.google.common.collect.s) it2;
                    if (!sVar.hasNext()) {
                        sb.append(']');
                        return sb.toString();
                    }
                    if (!z) {
                        sb.append(", ");
                    }
                    sb.append(sVar.next());
                    z = false;
                }
            default:
                return super.toString();
        }
    }
}
