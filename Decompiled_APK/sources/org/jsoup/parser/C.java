package org.jsoup.parser;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

/* loaded from: classes3.dex */
public class C extends ArrayList {
    public final /* synthetic */ int a;

    public /* synthetic */ C(int i) {
        this.a = i;
    }

    public boolean b() {
        return size() < 0;
    }

    @Override // java.util.ArrayList
    public Object clone() {
        switch (this.a) {
            case 1:
                C c = new C(size(), 1);
                Iterator<E> it2 = iterator();
                while (it2.hasNext()) {
                    c.add(((org.jsoup.nodes.i) it2.next()).clone());
                }
                return c;
            default:
                return super.clone();
        }
    }

    @Override // java.util.AbstractCollection
    public String toString() {
        switch (this.a) {
            case 1:
                StringBuilder sbB = org.jsoup.internal.a.b();
                Iterator<E> it2 = iterator();
                while (it2.hasNext()) {
                    org.jsoup.nodes.i iVar = (org.jsoup.nodes.i) it2.next();
                    if (sbB.length() != 0) {
                        sbB.append("\n");
                    }
                    sbB.append(iVar.s());
                }
                return org.jsoup.internal.a.g(sbB);
            default:
                return super.toString();
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C(int i, int i2) {
        super(i);
        this.a = i2;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C(Collection collection) {
        super(collection);
        this.a = 1;
    }
}
