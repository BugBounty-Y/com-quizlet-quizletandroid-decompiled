package com.google.android.gms.internal.mlkit_vision_barcode;

import java.util.Iterator;
import java.util.Set;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.y, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3300y extends AbstractC3252s implements Set {
    public transient AbstractC3292x b;

    @Override // java.util.Collection, java.util.Set
    public final boolean equals(Object obj) {
        if (obj != this && this != obj) {
            if (!(obj instanceof Set)) {
                return false;
            }
            Set set = (Set) obj;
            try {
                if (size() != set.size()) {
                    return false;
                }
                if (!containsAll(set)) {
                    return false;
                }
            } catch (ClassCastException | NullPointerException unused) {
                return false;
            }
        }
        return true;
    }

    @Override // java.util.Collection, java.util.Set
    public final int hashCode() {
        Iterator it2 = iterator();
        int iHashCode = 0;
        while (it2.hasNext()) {
            Object next = it2.next();
            iHashCode += next != null ? next.hashCode() : 0;
        }
        return iHashCode;
    }
}
