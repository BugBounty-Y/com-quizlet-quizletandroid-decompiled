package com.google.android.material.circularreveal;

import android.util.Property;

/* loaded from: classes2.dex */
public final class d extends Property {
    public static final d a = new d(f.class, "circularReveal");

    @Override // android.util.Property
    public final Object get(Object obj) {
        return ((g) obj).getRevealInfo();
    }

    @Override // android.util.Property
    public final void set(Object obj, Object obj2) {
        ((g) obj).setRevealInfo((f) obj2);
    }
}
