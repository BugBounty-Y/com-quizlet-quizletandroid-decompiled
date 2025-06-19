package com.google.android.gms.internal.mlkit_vision_barcode;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class W {
    public final EnumC3290w5 a;
    public final Boolean b;
    public final E7 c;
    public final B d;
    public final B e;

    public /* synthetic */ W(com.quizlet.data.repository.studysetwithcreatorinclass.g gVar) {
        this.a = (EnumC3290w5) gVar.b;
        this.b = (Boolean) gVar.c;
        this.c = (E7) gVar.d;
        this.d = (B) gVar.e;
        this.e = (B) gVar.f;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof W)) {
            return false;
        }
        W w = (W) obj;
        return com.google.android.gms.common.internal.u.l(this.a, w.a) && com.google.android.gms.common.internal.u.l(null, null) && com.google.android.gms.common.internal.u.l(this.b, w.b) && com.google.android.gms.common.internal.u.l(null, null) && com.google.android.gms.common.internal.u.l(this.c, w.c) && com.google.android.gms.common.internal.u.l(this.d, w.d) && com.google.android.gms.common.internal.u.l(this.e, w.e);
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, null, this.b, null, this.c, this.d, this.e});
    }
}
