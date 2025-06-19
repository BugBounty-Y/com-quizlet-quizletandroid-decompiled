package com.google.android.gms.internal.play_billing;

import java.io.Serializable;

/* renamed from: com.google.android.gms.internal.play_billing.v, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3841v implements Comparable, Serializable {
    public abstract int a(AbstractC3841v abstractC3841v);

    public abstract void b(StringBuilder sb);

    public abstract void c(StringBuilder sb);

    public final boolean equals(Object obj) {
        if (!(obj instanceof AbstractC3841v)) {
            return false;
        }
        try {
            return a((AbstractC3841v) obj) == 0;
        } catch (ClassCastException unused) {
            return false;
        }
    }

    public abstract int hashCode();
}
