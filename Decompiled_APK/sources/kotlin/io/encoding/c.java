package kotlin.io.encoding;

import java.nio.charset.Charset;
import kotlin.collections.AbstractC4916g;
import kotlin.collections.C4913d;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.CharsKt;
import kotlin.text.Charsets;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public class c {

    @NotNull
    public static final a c = new a(null);
    public static final byte[] d = {13, 10};
    public final boolean a;
    public final boolean b;

    static {
        b[] bVarArr = b.a;
        new c(true, false);
        new c(false, true);
    }

    public c(boolean z, boolean z2) {
        b[] bVarArr = b.a;
        this.a = z;
        this.b = z2;
        if (z && z2) {
            throw new IllegalArgumentException("Failed requirement.");
        }
    }

    public static byte[] a(a aVar, CharSequence source, int i, int i2) {
        byte[] source2;
        int i3;
        boolean z;
        int i4;
        int i5;
        int[] iArr;
        char c2;
        int i6;
        int i7 = -2;
        int i8 = 1;
        int i9 = 0;
        int i10 = (i2 & 2) != 0 ? 0 : i;
        int length = source.length();
        aVar.getClass();
        Intrinsics.checkNotNullParameter(source, "source");
        if (source instanceof String) {
            int length2 = ((String) source).length();
            AbstractC4916g.a.getClass();
            C4913d.a(i10, length, length2);
            String strSubstring = ((String) source).substring(i10, length);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
            Charset charset = Charsets.c;
            Intrinsics.e(strSubstring, "null cannot be cast to non-null type java.lang.String");
            source2 = strSubstring.getBytes(charset);
            Intrinsics.checkNotNullExpressionValue(source2, "getBytes(...)");
        } else {
            Intrinsics.checkNotNullParameter(source, "source");
            int length3 = source.length();
            AbstractC4916g.a.getClass();
            C4913d.a(i10, length, length3);
            byte[] bArr = new byte[length - i10];
            int i11 = 0;
            while (i10 < length) {
                char cCharAt = source.charAt(i10);
                if (cCharAt <= 255) {
                    bArr[i11] = (byte) cCharAt;
                    i11++;
                } else {
                    bArr[i11] = 63;
                    i11++;
                }
                i10++;
            }
            source2 = bArr;
        }
        int length4 = source2.length;
        Intrinsics.checkNotNullParameter(source2, "source");
        int length5 = source2.length;
        AbstractC4916g.a.getClass();
        C4913d.a(0, length4, length5);
        Intrinsics.checkNotNullParameter(source2, "source");
        boolean z2 = aVar.b;
        if (length4 == 0) {
            z = z2;
        } else {
            if (length4 == 1) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.f(length4, "Input should have at least 2 symbols for Base64 decoding, startIndex: 0, endIndex: "));
            }
            if (z2) {
                i3 = length4;
                int i12 = 0;
                while (true) {
                    if (i12 >= length4) {
                        break;
                    }
                    int i13 = d.b[source2[i12] & 255];
                    if (i13 < 0) {
                        if (i13 == -2) {
                            i3 -= length4 - i12;
                            break;
                        }
                        i3--;
                    }
                    i12++;
                }
            } else if (source2[length4 - 1] == 61) {
                i3 = length4 - 1;
                if (source2[length4 - 2] == 61) {
                    i3 = length4 - 2;
                }
            } else {
                i3 = length4;
            }
            z = z2;
            i9 = (int) ((i3 * 6) / 8);
        }
        byte[] bArr2 = new byte[i9];
        int[] iArr2 = aVar.a ? d.d : d.b;
        int i14 = -8;
        int i15 = -8;
        int i16 = 0;
        int i17 = 0;
        int i18 = 0;
        while (true) {
            int i19 = i8;
            if (i17 >= length4) {
                i4 = i7;
                i5 = 0;
                break;
            }
            if (i15 != i14 || (i6 = i17 + 3) >= length4) {
                iArr = iArr2;
            } else {
                iArr = iArr2;
                int i20 = i17 + 4;
                int i21 = (iArr[source2[i17 + 2] & 255] << 6) | (iArr2[source2[i17 + 1] & 255] << 12) | (iArr2[source2[i17] & 255] << 18) | iArr[source2[i6] & 255];
                if (i21 >= 0) {
                    bArr2[i16] = (byte) (i21 >> 16);
                    int i22 = i16 + 2;
                    bArr2[i16 + 1] = (byte) (i21 >> 8);
                    i16 += 3;
                    bArr2[i22] = (byte) i21;
                    iArr2 = iArr;
                    i8 = i19;
                    i17 = i20;
                    i7 = -2;
                }
                i14 = -8;
            }
            int i23 = source2[i17] & 255;
            int i24 = iArr[i23];
            if (i24 >= 0) {
                c2 = '=';
                i17++;
                i18 = (i18 << 6) | i24;
                int i25 = i15 + 6;
                if (i25 >= 0) {
                    bArr2[i16] = (byte) (i18 >>> i25);
                    i18 &= (i19 << i25) - 1;
                    i15 -= 2;
                    i16++;
                    i7 = -2;
                    i8 = i19;
                    i14 = -8;
                    iArr2 = iArr;
                } else {
                    iArr2 = iArr;
                    i15 = i25;
                }
            } else if (i24 != -2) {
                c2 = '=';
                if (!z) {
                    StringBuilder sb = new StringBuilder("Invalid symbol '");
                    sb.append((char) i23);
                    sb.append("'(");
                    String string = Integer.toString(i23, CharsKt.checkRadix(8));
                    Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                    sb.append(string);
                    sb.append(") at index ");
                    sb.append(i17);
                    throw new IllegalArgumentException(sb.toString());
                }
                i17++;
                iArr2 = iArr;
            } else {
                if (i15 == -8) {
                    throw new IllegalArgumentException(android.support.v4.media.session.a.f(i17, "Redundant pad character at index "));
                }
                if (i15 == -6) {
                    b[] bVarArr = b.a;
                } else if (i15 == -4) {
                    b[] bVarArr2 = b.a;
                    i17++;
                    if (z) {
                        while (i17 < length4) {
                            if (d.b[source2[i17] & 255] != -1) {
                                break;
                            }
                            i17++;
                        }
                    }
                    if (i17 == length4 || source2[i17] != 61) {
                        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i17, "Missing one pad character at index "));
                    }
                } else if (i15 != -2) {
                    throw new IllegalStateException("Unreachable");
                }
                i17++;
                i5 = i19;
                i4 = -2;
            }
            i8 = i19;
            i7 = -2;
            i14 = -8;
        }
        if (i15 == i4) {
            throw new IllegalArgumentException("The last unit of input does not have enough bits");
        }
        if (i15 != -8 && i5 == 0) {
            b[] bVarArr3 = b.a;
            throw new IllegalArgumentException("The padding option is set to PRESENT, but the input is not properly padded");
        }
        if (i18 != 0) {
            throw new IllegalArgumentException("The pad bits must be zeros");
        }
        if (z) {
            while (i17 < length4) {
                if (d.b[source2[i17] & 255] != -1) {
                    break;
                }
                i17++;
            }
        }
        if (i17 >= length4) {
            if (i16 == i9) {
                return bArr2;
            }
            throw new IllegalStateException("Check failed.");
        }
        int i26 = source2[i17] & 255;
        StringBuilder sb2 = new StringBuilder("Symbol '");
        sb2.append((char) i26);
        sb2.append("'(");
        String string2 = Integer.toString(i26, CharsKt.checkRadix(8));
        Intrinsics.checkNotNullExpressionValue(string2, "toString(...)");
        sb2.append(string2);
        sb2.append(") at index ");
        throw new IllegalArgumentException(android.support.v4.media.session.a.r(sb2, i17 - 1, " is prohibited after the pad character"));
    }

    public final int b(int i) {
        int i2 = (i / 3) * 4;
        if (i % 3 != 0) {
            b[] bVarArr = b.a;
            i2 += 4;
        }
        if (this.b) {
            i2 += ((i2 - 1) / 76) * 2;
        }
        if (i2 >= 0) {
            return i2;
        }
        throw new IllegalArgumentException("Input is too big");
    }
}
