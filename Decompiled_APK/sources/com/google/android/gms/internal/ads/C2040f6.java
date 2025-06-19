package com.google.android.gms.internal.ads;

import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Locale;

/* renamed from: com.google.android.gms.internal.ads.f6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2040f6 {
    public static final C2040f6 d = new C2040f6(1.0f, 1.0f);
    public final float a;
    public final float b;
    public final int c;

    static {
        String str = Yo.a;
        Integer.toString(0, 36);
        Integer.toString(1, 36);
    }

    public C2040f6(float f, float f2) {
        AbstractC1795We.B(f > DefinitionKt.NO_Float_VALUE);
        AbstractC1795We.B(f2 > DefinitionKt.NO_Float_VALUE);
        this.a = f;
        this.b = f2;
        this.c = Math.round(f * 1000.0f);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C2040f6.class == obj.getClass()) {
            C2040f6 c2040f6 = (C2040f6) obj;
            if (this.a == c2040f6.a && this.b == c2040f6.b) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Float.floatToRawIntBits(this.b) + ((Float.floatToRawIntBits(this.a) + 527) * 31);
    }

    public final String toString() {
        Object[] objArr = {Float.valueOf(this.a), Float.valueOf(this.b)};
        String str = Yo.a;
        return String.format(Locale.US, "PlaybackParameters(speed=%.2f, pitch=%.2f)", objArr);
    }
}
