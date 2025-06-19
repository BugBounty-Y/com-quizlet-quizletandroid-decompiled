package com.bumptech.glide.manager;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class n implements a {
    public final /* synthetic */ p a;

    public n(p pVar) {
        this.a = pVar;
    }

    @Override // com.bumptech.glide.manager.a
    public final void a(boolean z) {
        ArrayList arrayList;
        com.bumptech.glide.util.m.a();
        synchronized (this.a) {
            arrayList = new ArrayList((HashSet) this.a.c);
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            ((a) it2.next()).a(z);
        }
    }
}
