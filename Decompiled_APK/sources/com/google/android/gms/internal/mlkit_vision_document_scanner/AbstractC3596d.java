package com.google.android.gms.internal.mlkit_vision_document_scanner;

import java.util.Iterator;
import java.util.Set;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3596d extends x7 implements Set {
    public transient AbstractC3588c b;

    @Override // java.util.Collection, java.util.Set
    public final boolean equals(Object obj) {
        if (obj == this || obj == this) {
            return true;
        }
        if (obj instanceof Set) {
            Set set = (Set) obj;
            try {
                if (size() == set.size()) {
                    return containsAll(set);
                }
            } catch (ClassCastException | NullPointerException unused) {
            }
        }
        return false;
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
