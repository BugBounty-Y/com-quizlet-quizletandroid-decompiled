package androidx.compose.ui.graphics;

import androidx.collection.C0223v;
import androidx.compose.animation.d0;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3320b;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.compose.ui.graphics.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0861v {
    public static final long b = F.d(4278190080L);
    public static final long c;
    public static final long d;
    public static final long e;
    public static final long f;
    public static final long g;
    public static final /* synthetic */ int h = 0;
    public final long a;

    static {
        F.d(4282664004L);
        F.d(4287137928L);
        F.d(4291611852L);
        c = F.d(4294967295L);
        d = F.d(4294901760L);
        F.d(4278255360L);
        e = F.d(4278190335L);
        F.d(4294967040L);
        F.d(4278255615L);
        F.d(4294902015L);
        f = F.c(0);
        g = F.b(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, androidx.compose.ui.graphics.colorspace.d.s);
    }

    public /* synthetic */ C0861v(long j) {
        this.a = j;
    }

    public static final long a(long j, androidx.compose.ui.graphics.colorspace.c cVar) {
        androidx.compose.ui.graphics.colorspace.g gVarE;
        androidx.compose.ui.graphics.colorspace.c cVarF = f(j);
        int i = cVarF.c;
        int i2 = cVar.c;
        if ((i | i2) < 0) {
            gVarE = androidx.compose.ui.graphics.colorspace.j.e(cVarF, cVar);
        } else {
            C0223v c0223v = androidx.compose.ui.graphics.colorspace.h.a;
            int i3 = i | (i2 << 6);
            Object objE = c0223v.e(i3);
            if (objE == null) {
                objE = androidx.compose.ui.graphics.colorspace.j.e(cVarF, cVar);
                c0223v.h(i3, objE);
            }
            gVarE = (androidx.compose.ui.graphics.colorspace.g) objE;
        }
        return gVarE.a(j);
    }

    public static long b(long j, float f2) {
        return F.b(h(j), g(j), e(j), f2, f(j));
    }

    public static final boolean c(long j, long j2) {
        kotlin.C c2 = kotlin.D.b;
        return j == j2;
    }

    public static final float d(long j) {
        float fC;
        float f2;
        long j2 = 63 & j;
        kotlin.C c2 = kotlin.D.b;
        if (j2 == 0) {
            fC = (float) AbstractC3320b.c((j >>> 56) & 255);
            f2 = 255.0f;
        } else {
            fC = (float) AbstractC3320b.c((j >>> 6) & 1023);
            f2 = 1023.0f;
        }
        return fC / f2;
    }

    public static final float e(long j) {
        int i;
        int i2;
        int i3;
        long j2 = 63 & j;
        kotlin.C c2 = kotlin.D.b;
        if (j2 == 0) {
            return ((float) AbstractC3320b.c((j >>> 32) & 255)) / 255.0f;
        }
        short s = (short) ((j >>> 16) & 65535);
        int i4 = 32768 & s;
        int i5 = ((65535 & s) >>> 10) & 31;
        int i6 = s & 1023;
        if (i5 != 0) {
            int i7 = i6 << 13;
            if (i5 == 31) {
                i = 255;
                if (i7 != 0) {
                    i7 |= 4194304;
                }
            } else {
                i = i5 + ContentType.LONG_FORM_ON_DEMAND;
            }
            int i8 = i;
            i2 = i7;
            i3 = i8;
        } else {
            if (i6 != 0) {
                float fIntBitsToFloat = Float.intBitsToFloat(i6 + 1056964608) - D.a;
                return i4 == 0 ? fIntBitsToFloat : -fIntBitsToFloat;
            }
            i3 = 0;
            i2 = 0;
        }
        return Float.intBitsToFloat((i3 << 23) | (i4 << 16) | i2);
    }

    public static final androidx.compose.ui.graphics.colorspace.c f(long j) {
        float[] fArr = androidx.compose.ui.graphics.colorspace.d.a;
        kotlin.C c2 = kotlin.D.b;
        return androidx.compose.ui.graphics.colorspace.d.u[(int) (j & 63)];
    }

    public static final float g(long j) {
        int i;
        int i2;
        int i3;
        long j2 = 63 & j;
        kotlin.C c2 = kotlin.D.b;
        if (j2 == 0) {
            return ((float) AbstractC3320b.c((j >>> 40) & 255)) / 255.0f;
        }
        short s = (short) ((j >>> 32) & 65535);
        int i4 = 32768 & s;
        int i5 = ((65535 & s) >>> 10) & 31;
        int i6 = s & 1023;
        if (i5 != 0) {
            int i7 = i6 << 13;
            if (i5 == 31) {
                i = 255;
                if (i7 != 0) {
                    i7 |= 4194304;
                }
            } else {
                i = i5 + ContentType.LONG_FORM_ON_DEMAND;
            }
            int i8 = i;
            i2 = i7;
            i3 = i8;
        } else {
            if (i6 != 0) {
                float fIntBitsToFloat = Float.intBitsToFloat(i6 + 1056964608) - D.a;
                return i4 == 0 ? fIntBitsToFloat : -fIntBitsToFloat;
            }
            i3 = 0;
            i2 = 0;
        }
        return Float.intBitsToFloat((i3 << 23) | (i4 << 16) | i2);
    }

    public static final float h(long j) {
        int i;
        int i2;
        int i3;
        long j2 = 63 & j;
        kotlin.C c2 = kotlin.D.b;
        if (j2 == 0) {
            return ((float) AbstractC3320b.c((j >>> 48) & 255)) / 255.0f;
        }
        short s = (short) ((j >>> 48) & 65535);
        int i4 = 32768 & s;
        int i5 = ((65535 & s) >>> 10) & 31;
        int i6 = s & 1023;
        if (i5 != 0) {
            int i7 = i6 << 13;
            if (i5 == 31) {
                i = 255;
                if (i7 != 0) {
                    i7 |= 4194304;
                }
            } else {
                i = i5 + ContentType.LONG_FORM_ON_DEMAND;
            }
            int i8 = i;
            i2 = i7;
            i3 = i8;
        } else {
            if (i6 != 0) {
                float fIntBitsToFloat = Float.intBitsToFloat(i6 + 1056964608) - D.a;
                return i4 == 0 ? fIntBitsToFloat : -fIntBitsToFloat;
            }
            i3 = 0;
            i2 = 0;
        }
        return Float.intBitsToFloat((i3 << 23) | (i4 << 16) | i2);
    }

    public static String i(long j) {
        StringBuilder sb = new StringBuilder("Color(");
        sb.append(h(j));
        sb.append(", ");
        sb.append(g(j));
        sb.append(", ");
        sb.append(e(j));
        sb.append(", ");
        sb.append(d(j));
        sb.append(", ");
        return d0.r(sb, f(j).a, ')');
    }

    public final boolean equals(Object obj) {
        if (obj instanceof C0861v) {
            return this.a == ((C0861v) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        kotlin.C c2 = kotlin.D.b;
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return i(this.a);
    }
}
