package com.quizlet.features.match.data;

import com.google.android.gms.internal.mlkit_vision_barcode.N6;

/* renamed from: com.quizlet.features.match.data.n, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4358n extends N6 {
    public final boolean a;

    public C4358n(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4358n) && this.a == ((C4358n) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("Selectable(isSelected="), this.a);
    }
}
