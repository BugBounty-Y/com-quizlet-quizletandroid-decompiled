package com.quizlet.features.match.data;

import com.google.android.gms.internal.mlkit_vision_barcode.N6;

/* renamed from: com.quizlet.features.match.data.k, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4355k {
    public N6 a = new C4358n(false);

    public final boolean a() {
        N6 n6 = this.a;
        C4358n c4358n = n6 instanceof C4358n ? (C4358n) n6 : null;
        if (c4358n != null) {
            return c4358n.a;
        }
        return false;
    }

    public final void b(boolean z) {
        this.a = new C4358n(z);
    }
}
