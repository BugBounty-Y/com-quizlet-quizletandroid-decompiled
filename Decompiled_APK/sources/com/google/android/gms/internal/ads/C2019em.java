package com.google.android.gms.internal.ads;

import android.graphics.drawable.Drawable;

/* renamed from: com.google.android.gms.internal.ads.em, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2019em {
    public final String a;
    public final String b;
    public final Drawable c;

    public C2019em(String str, String str2, Drawable drawable) {
        this.a = str;
        if (str2 == null) {
            throw new NullPointerException("Null imageUrl");
        }
        this.b = str2;
        this.c = drawable;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C2019em) {
            C2019em c2019em = (C2019em) obj;
            String str = this.a;
            if (str != null ? str.equals(c2019em.a) : c2019em.a == null) {
                if (this.b.equals(c2019em.b)) {
                    Drawable drawable = c2019em.c;
                    Drawable drawable2 = this.c;
                    if (drawable2 != null ? drawable2.equals(drawable) : drawable == null) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (((str == null ? 0 : str.hashCode()) ^ 1000003) * 1000003) ^ this.b.hashCode();
        Drawable drawable = this.c;
        return (drawable != null ? drawable.hashCode() : 0) ^ (iHashCode * 1000003);
    }

    public final String toString() {
        String strValueOf = String.valueOf(this.c);
        StringBuilder sb = new StringBuilder("OfflineAdAssets{advertiserName=");
        sb.append(this.a);
        sb.append(", imageUrl=");
        return androidx.compose.ui.node.B.j(sb, this.b, ", icon=", strValueOf, "}");
    }
}
