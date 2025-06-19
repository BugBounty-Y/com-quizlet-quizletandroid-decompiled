package com.squareup.moshi;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes3.dex */
public final class C {
    public final ArrayList a = new ArrayList();
    public final ArrayDeque b = new ArrayDeque();
    public boolean c;
    public final /* synthetic */ D d;

    public C(D d) {
        this.d = d;
    }

    public final IllegalArgumentException a(IllegalArgumentException illegalArgumentException) {
        if (!this.c) {
            this.c = true;
            ArrayDeque arrayDeque = this.b;
            if (arrayDeque.size() != 1 || ((B) arrayDeque.getFirst()).b != null) {
                StringBuilder sb = new StringBuilder(illegalArgumentException.getMessage());
                Iterator itDescendingIterator = arrayDeque.descendingIterator();
                while (itDescendingIterator.hasNext()) {
                    B b = (B) itDescendingIterator.next();
                    sb.append("\nfor ");
                    sb.append(b.a);
                    String str = b.b;
                    if (str != null) {
                        sb.append(' ');
                        sb.append(str);
                    }
                }
                return new IllegalArgumentException(sb.toString(), illegalArgumentException);
            }
        }
        return illegalArgumentException;
    }

    public final void b(boolean z) {
        this.b.removeLast();
        if (this.b.isEmpty()) {
            this.d.b.remove();
            if (z) {
                synchronized (this.d.c) {
                    try {
                        int size = this.a.size();
                        for (int i = 0; i < size; i++) {
                            B b = (B) this.a.get(i);
                            l lVar = (l) this.d.c.put(b.c, b.d);
                            if (lVar != null) {
                                b.d = lVar;
                                this.d.c.put(b.c, lVar);
                            }
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
            }
        }
    }
}
