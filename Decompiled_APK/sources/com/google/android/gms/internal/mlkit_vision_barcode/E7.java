package com.google.android.gms.internal.mlkit_vision_barcode;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class E7 {
    public final B a;

    public /* synthetic */ E7(com.quizlet.data.repository.school.membership.a aVar) {
        this.a = (B) aVar.b;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof E7) {
            return com.google.android.gms.common.internal.u.l(this.a, ((E7) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a});
    }
}
