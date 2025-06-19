package com.braze.triggers.conditions.logical;

import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class c extends b {
    public c(ArrayList arrayList) {
        super(arrayList);
    }

    @Override // com.braze.triggers.conditions.c
    public final boolean a(com.braze.triggers.events.b bVar) {
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            if (((com.braze.triggers.conditions.c) it2.next()).a(bVar)) {
                return true;
            }
        }
        return false;
    }
}
