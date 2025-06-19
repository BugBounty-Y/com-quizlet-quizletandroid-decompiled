package com.google.android.gms.internal.ads;

import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.cx, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1943cx extends AbstractC2804ww {
    public final Ew a;
    public final String b;
    public final C2332lw c;
    public final AbstractC2804ww d;

    public C1943cx(Ew ew, String str, C2332lw c2332lw, AbstractC2804ww abstractC2804ww) {
        this.a = ew;
        this.b = str;
        this.c = c2332lw;
        this.d = abstractC2804ww;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2547qw
    public final boolean a() {
        return this.a != Ew.l;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C1943cx)) {
            return false;
        }
        C1943cx c1943cx = (C1943cx) obj;
        return c1943cx.c.equals(this.c) && c1943cx.d.equals(this.d) && c1943cx.b.equals(this.b) && c1943cx.a.equals(this.a);
    }

    public final int hashCode() {
        return Objects.hash(C1943cx.class, this.b, this.c, this.d, this.a);
    }

    public final String toString() {
        String strValueOf = String.valueOf(this.c);
        String strValueOf2 = String.valueOf(this.d);
        String strValueOf3 = String.valueOf(this.a);
        StringBuilder sb = new StringBuilder("LegacyKmsEnvelopeAead Parameters (kekUri: ");
        androidx.compose.ui.node.B.u(sb, this.b, ", dekParsingStrategy: ", strValueOf, ", dekParametersForNewKeys: ");
        return androidx.compose.ui.node.B.j(sb, strValueOf2, ", variant: ", strValueOf3, ")");
    }
}
