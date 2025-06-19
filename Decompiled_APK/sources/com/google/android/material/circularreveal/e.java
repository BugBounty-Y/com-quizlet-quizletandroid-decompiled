package com.google.android.material.circularreveal;

import android.util.Property;

/* loaded from: classes2.dex */
public final class e extends Property {
    public static final e a = new e(Integer.class, "circularRevealScrimColor");

    @Override // android.util.Property
    public final Object get(Object obj) {
        return Integer.valueOf(((g) obj).getCircularRevealScrimColor());
    }

    @Override // android.util.Property
    public final void set(Object obj, Object obj2) {
        ((g) obj).setCircularRevealScrimColor(((Integer) obj2).intValue());
    }
}
