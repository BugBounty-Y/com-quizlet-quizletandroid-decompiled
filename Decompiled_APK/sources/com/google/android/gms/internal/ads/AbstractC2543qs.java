package com.google.android.gms.internal.ads;

import android.content.Context;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;

/* renamed from: com.google.android.gms.internal.ads.qs, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2543qs {
    public static int a(Set set) {
        Iterator it2 = set.iterator();
        int iHashCode = 0;
        while (it2.hasNext()) {
            Object next = it2.next();
            iHashCode += next != null ? next.hashCode() : 0;
        }
        return iHashCode;
    }

    public static zzfpo b(Context context, int i, String str, String str2, androidx.browser.customtabs.k kVar) {
        zzfpo zzfpoVar;
        C2500ps c2500ps = new C2500ps(context, i, str, str2, kVar);
        try {
            zzfpoVar = (zzfpo) c2500ps.d.poll(50000L, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            c2500ps.b(2009, c2500ps.g, e);
            zzfpoVar = null;
        }
        c2500ps.b(3004, c2500ps.g, null);
        if (zzfpoVar != null) {
            if (zzfpoVar.c == 7) {
                androidx.browser.customtabs.k.e = 3;
            } else {
                androidx.browser.customtabs.k.e = 2;
            }
        }
        return zzfpoVar == null ? new zzfpo() : zzfpoVar;
    }

    public static Object c(Ju ju, String str) {
        C2502pu c2502pu = new C2502pu(ju.a, ju.b);
        return c2502pu.hasNext() ? c2502pu.next() : str;
    }

    public static Object d(Future future) {
        Object obj;
        boolean z = false;
        while (true) {
            try {
                obj = future.get();
                break;
            } catch (InterruptedException unused) {
                z = true;
            } catch (Throwable th) {
                if (z) {
                    Thread.currentThread().interrupt();
                }
                throw th;
            }
        }
        if (z) {
            Thread.currentThread().interrupt();
        }
        return obj;
    }

    public static String e(BA ba) {
        StringBuilder sb = new StringBuilder(ba.g());
        for (int i = 0; i < ba.g(); i++) {
            byte b = ba.b(i);
            if (b == 34) {
                sb.append("\\\"");
            } else if (b == 39) {
                sb.append("\\'");
            } else if (b != 92) {
                switch (b) {
                    case 7:
                        sb.append("\\a");
                        break;
                    case 8:
                        sb.append("\\b");
                        break;
                    case 9:
                        sb.append("\\t");
                        break;
                    case 10:
                        sb.append("\\n");
                        break;
                    case 11:
                        sb.append("\\v");
                        break;
                    case 12:
                        sb.append("\\f");
                        break;
                    case 13:
                        sb.append("\\r");
                        break;
                    default:
                        if (b < 32 || b > 126) {
                            sb.append('\\');
                            sb.append((char) (((b >>> 6) & 3) + 48));
                            sb.append((char) (((b >>> 3) & 7) + 48));
                            sb.append((char) ((b & 7) + 48));
                            break;
                        } else {
                            sb.append((char) b);
                            break;
                        }
                }
            } else {
                sb.append("\\\\");
            }
        }
        return sb.toString();
    }

    public static String f(String str) {
        int length = str.length();
        int i = 0;
        while (i < length) {
            if (y(str.charAt(i))) {
                char[] charArray = str.toCharArray();
                while (i < length) {
                    char c = charArray[i];
                    if (y(c)) {
                        charArray[i] = (char) (c ^ ' ');
                    }
                    i++;
                }
                return String.valueOf(charArray);
            }
            i++;
        }
        return str;
    }

    public static void g(int i, String str) {
        if (i >= 0) {
            return;
        }
        throw new IllegalArgumentException(str + " cannot be negative but was: " + i);
    }

    public static void h(long j, String str) {
        if (j >= 0) {
            return;
        }
        throw new IllegalArgumentException(str + " (" + j + ") must be >= 0");
    }

    public static boolean i(String str) {
        return str == null || str.isEmpty();
    }

    public static /* synthetic */ boolean j(AtomicReferenceFieldUpdater atomicReferenceFieldUpdater, AbstractC2674tv abstractC2674tv, Object obj, Object obj2) {
        while (!atomicReferenceFieldUpdater.compareAndSet(abstractC2674tv, obj, obj2)) {
            if (atomicReferenceFieldUpdater.get(abstractC2674tv) != obj && atomicReferenceFieldUpdater.get(abstractC2674tv) != obj) {
                return false;
            }
        }
        return true;
    }

    public static byte[] k(String str) {
        if (str.length() % 2 != 0) {
            throw new IllegalArgumentException("Expected a string of even length");
        }
        int length = str.length() / 2;
        byte[] bArr = new byte[length];
        for (int i = 0; i < length; i++) {
            int i2 = i + i;
            int iDigit = Character.digit(str.charAt(i2), 16);
            int iDigit2 = Character.digit(str.charAt(i2 + 1), 16);
            if (iDigit == -1 || iDigit2 == -1) {
                throw new IllegalArgumentException("input is not hexadecimal");
            }
            bArr[i] = (byte) ((iDigit * 16) + iDigit2);
        }
        return bArr;
    }

    public static byte[] l(byte[] bArr, byte[] bArr2) {
        long jS = s(0, bArr) & 67108863;
        int i = 3;
        long jS2 = (s(3, bArr) >> 2) & 67108611;
        long jS3 = (s(6, bArr) >> 4) & 67092735;
        long jS4 = (s(9, bArr) >> 6) & 66076671;
        long jS5 = (s(12, bArr) >> 8) & 1048575;
        byte[] bArr3 = new byte[17];
        long j = 0;
        long j2 = 0;
        long j3 = 0;
        long j4 = 0;
        long j5 = 0;
        int i2 = 0;
        while (true) {
            int length = bArr2.length;
            if (i2 >= length) {
                long j6 = j + (j2 >> 26);
                long j7 = j6 & 67108863;
                long j8 = j3 + (j6 >> 26);
                long j9 = j8 & 67108863;
                long j10 = j4 + (j8 >> 26);
                long j11 = j10 & 67108863;
                long j12 = ((j10 >> 26) * 5) + j5;
                long j13 = j12 >> 26;
                long j14 = j12 & 67108863;
                long j15 = j14 + 5;
                long j16 = (j2 & 67108863) + j13;
                long j17 = j16 + (j15 >> 26);
                long j18 = j7 + (j17 >> 26);
                long j19 = j9 + (j18 >> 26);
                long j20 = (j11 + (j19 >> 26)) - 67108864;
                long j21 = j20 >> 63;
                long j22 = ~j21;
                long j23 = (j16 & j21) | (j17 & 67108863 & j22);
                long j24 = (j7 & j21) | (j18 & 67108863 & j22);
                long j25 = (j9 & j21) | (j19 & 67108863 & j22);
                long j26 = (j11 & j21) | (j20 & j22);
                long jS6 = s(16, bArr) + (((j14 & j21) | (j15 & 67108863 & j22) | (j23 << 26)) & 4294967295L);
                long jS7 = s(20, bArr) + (((j23 >> 6) | (j24 << 20)) & 4294967295L);
                long jS8 = s(24, bArr);
                long jS9 = s(28, bArr) + (((j25 >> 18) | (j26 << 8)) & 4294967295L);
                byte[] bArr4 = new byte[16];
                w(jS6 & 4294967295L, bArr4, 0);
                long j27 = jS7 + (jS6 >> 32);
                w(j27 & 4294967295L, bArr4, 4);
                long j28 = jS8 + (((j24 >> 12) | (j25 << 14)) & 4294967295L) + (j27 >> 32);
                w(j28 & 4294967295L, bArr4, 8);
                w((jS9 + (j28 >> 32)) & 4294967295L, bArr4, 12);
                return bArr4;
            }
            int iMin = Math.min(16, length - i2);
            System.arraycopy(bArr2, i2, bArr3, 0, iMin);
            bArr3[iMin] = 1;
            if (iMin != 16) {
                Arrays.fill(bArr3, iMin + 1, 17, (byte) 0);
            }
            long j29 = jS5 * 5;
            long j30 = jS4 * 5;
            long j31 = jS3 * 5;
            long jS10 = j5 + (s(0, bArr3) & 67108863);
            long jS11 = j2 + ((s(i, bArr3) >> 2) & 67108863);
            long jS12 = j + ((s(6, bArr3) >> 4) & 67108863);
            long jS13 = j3 + ((s(9, bArr3) >> 6) & 67108863);
            long j32 = jS2;
            long jS14 = j4 + (((s(12, bArr3) >> 8) & 67108863) | (bArr3[16] << 24));
            long j33 = jS11 * jS;
            long j34 = jS11 * j32;
            long j35 = jS12 * jS;
            long j36 = jS11 * jS3;
            long j37 = jS12 * j32;
            long j38 = jS13 * jS;
            long j39 = jS11 * jS4;
            long j40 = jS12 * jS3;
            long j41 = jS13 * j32;
            long j42 = jS14 * jS;
            long j43 = (jS2 * 5 * jS14) + (jS13 * j31) + (jS12 * j30) + (jS11 * j29) + (jS10 * jS);
            long j44 = j43 & 67108863;
            long j45 = jS13 * j30;
            long j46 = j31 * jS14;
            long j47 = j46 + j45 + (jS12 * j29) + (jS10 * j32) + j33 + (j43 >> 26);
            long j48 = j30 * jS14;
            long j49 = j48 + (jS13 * j29) + (jS10 * jS3) + j34 + j35 + (j47 >> 26);
            long j50 = (jS14 * j29) + (jS10 * jS4) + j36 + j37 + j38 + (j49 >> 26);
            long j51 = (jS10 * jS5) + j39 + j40 + j41 + j42 + (j50 >> 26);
            long j52 = ((j51 >> 26) * 5) + j44;
            j2 = (j47 & 67108863) + (j52 >> 26);
            i2 += 16;
            j = j49 & 67108863;
            j3 = j50 & 67108863;
            j4 = j51 & 67108863;
            j5 = j52 & 67108863;
            jS2 = j32;
            i = 3;
        }
    }

    public static Ju m(AbstractC2459ou abstractC2459ou, AbstractC2459ou abstractC2459ou2) {
        AbstractC1981ds.x(abstractC2459ou, "set1");
        AbstractC1981ds.x(abstractC2459ou2, "set2");
        return new Ju(abstractC2459ou, abstractC2459ou2);
    }

    public static String n(String str) {
        int length = str.length();
        int i = 0;
        while (i < length) {
            char cCharAt = str.charAt(i);
            if (cCharAt >= 'a' && cCharAt <= 'z') {
                char[] charArray = str.toCharArray();
                while (i < length) {
                    char c = charArray[i];
                    if (c >= 'a' && c <= 'z') {
                        charArray[i] = (char) (c ^ ' ');
                    }
                    i++;
                }
                return String.valueOf(charArray);
            }
            i++;
        }
        return str;
    }

    public static LinkedHashMap o(int i) {
        return new LinkedHashMap(i < 3 ? i + 1 : i < 1073741824 ? (int) ((i / 0.75f) + 1.0f) : SubsamplingScaleImageView.TILE_SIZE_AUTO);
    }

    public static void p(Object obj, Object obj2) {
        if (obj == null) {
            throw new NullPointerException("null key in entry: null=".concat(String.valueOf(obj2)));
        }
        if (obj2 == null) {
            throw new NullPointerException(android.support.v4.media.session.a.B("null value in entry: ", obj.toString(), "=null"));
        }
    }

    public static void q(boolean z) {
        if (!z) {
            throw new ArithmeticException("mode was UNNECESSARY, but rounding was necessary");
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0034  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x003c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static int r(int r2) {
        /*
            r0 = 20
            r1 = -2147483647(0xffffffff80000001, float:-1.4E-45)
            if (r2 == r0) goto L40
            r0 = 30
            if (r2 == r0) goto L3c
            switch(r2) {
                case 5: goto L38;
                case 6: goto L34;
                case 7: goto L30;
                case 8: goto L3c;
                case 9: goto L2c;
                case 10: goto L28;
                case 11: goto L25;
                case 12: goto L22;
                default: goto Le;
            }
        Le:
            switch(r2) {
                case 14: goto L1e;
                case 15: goto L1b;
                case 16: goto L17;
                case 17: goto L13;
                case 18: goto L34;
                default: goto L11;
            }
        L11:
            r2 = r1
            goto L43
        L13:
            r2 = 336000(0x52080, float:4.70836E-40)
            goto L43
        L17:
            r2 = 256000(0x3e800, float:3.58732E-40)
            goto L43
        L1b:
            r2 = 8000(0x1f40, float:1.121E-41)
            goto L43
        L1e:
            r2 = 3062500(0x2ebae4, float:4.291477E-39)
            goto L43
        L22:
            r2 = 7000(0x1b58, float:9.809E-42)
            goto L43
        L25:
            r2 = 16000(0x3e80, float:2.2421E-41)
            goto L43
        L28:
            r2 = 100000(0x186a0, float:1.4013E-40)
            goto L43
        L2c:
            r2 = 40000(0x9c40, float:5.6052E-41)
            goto L43
        L30:
            r2 = 192000(0x2ee00, float:2.6905E-40)
            goto L43
        L34:
            r2 = 768000(0xbb800, float:1.076197E-39)
            goto L43
        L38:
            r2 = 80000(0x13880, float:1.12104E-40)
            goto L43
        L3c:
            r2 = 2250000(0x225510, float:3.152922E-39)
            goto L43
        L40:
            r2 = 63750(0xf906, float:8.9333E-41)
        L43:
            if (r2 == r1) goto L47
            r0 = 1
            goto L48
        L47:
            r0 = 0
        L48:
            com.google.android.gms.internal.ads.AbstractC1795We.L(r0)
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC2543qs.r(int):int");
    }

    public static long s(int i, byte[] bArr) {
        int i2 = bArr[i] & 255;
        int i3 = bArr[i + 1] & 255;
        int i4 = bArr[i + 2] & 255;
        return (((bArr[i + 3] & 255) << 24) | (i3 << 8) | i2 | (i4 << 16)) & 4294967295L;
    }

    public static Ku t(Set set, InterfaceC2715ut interfaceC2715ut) {
        if (!(set instanceof SortedSet)) {
            if (!(set instanceof Ku)) {
                set.getClass();
                return new Ku(set, interfaceC2715ut);
            }
            Ku ku = (Ku) set;
            InterfaceC2715ut interfaceC2715ut2 = ku.b;
            interfaceC2715ut2.getClass();
            return new Ku(ku.a, new C2758vt(Arrays.asList(interfaceC2715ut2, interfaceC2715ut)));
        }
        Set set2 = (SortedSet) set;
        if (!(set2 instanceof Ku)) {
            set2.getClass();
            return new Lu(set2, interfaceC2715ut);
        }
        Ku ku2 = (Ku) set2;
        InterfaceC2715ut interfaceC2715ut3 = ku2.b;
        interfaceC2715ut3.getClass();
        return new Lu((SortedSet) ku2.a, new C2758vt(Arrays.asList(interfaceC2715ut3, interfaceC2715ut)));
    }

    public static void u(List list, InterfaceC2715ut interfaceC2715ut, int i, int i2) {
        int size = list.size();
        while (true) {
            size--;
            if (size <= i2) {
                break;
            } else if (interfaceC2715ut.b(list.get(size))) {
                list.remove(size);
            }
        }
        while (true) {
            i2--;
            if (i2 < i) {
                return;
            } else {
                list.remove(i2);
            }
        }
    }

    public static boolean v(CharSequence charSequence, String str) {
        char c;
        int length = str.length();
        if (str == charSequence) {
            return true;
        }
        if (length == charSequence.length()) {
            for (int i = 0; i < length; i++) {
                if (str.charAt(i) == charSequence.charAt(i) || ((c = (char) ((r3 | ' ') - 97)) < 26 && c == ((char) ((r4 | ' ') - 97)))) {
                }
            }
            return true;
        }
        return false;
    }

    public static void w(long j, byte[] bArr, int i) {
        for (int i2 = 0; i2 < 4; i2++) {
            bArr[i + i2] = (byte) (255 & j);
            j >>= 8;
        }
    }

    public static boolean x(Set set, Object obj) {
        if (set == obj) {
            return true;
        }
        if (!(obj instanceof Set)) {
            return false;
        }
        Set set2 = (Set) obj;
        try {
            if (set.size() == set2.size()) {
                return set.containsAll(set2);
            }
            return false;
        } catch (ClassCastException | NullPointerException unused) {
            return false;
        }
    }

    public static boolean y(char c) {
        return c >= 'A' && c <= 'Z';
    }

    public static boolean z(Mu mu, Collection collection) {
        collection.getClass();
        if (collection instanceof InterfaceC2888yu) {
            collection = ((InterfaceC2888yu) collection).zza();
        }
        boolean zRemove = false;
        if (!(collection instanceof Set) || collection.size() <= mu.size()) {
            Iterator it2 = collection.iterator();
            while (it2.hasNext()) {
                zRemove |= mu.remove(it2.next());
            }
            return zRemove;
        }
        Iterator<E> it3 = mu.iterator();
        collection.getClass();
        while (it3.hasNext()) {
            if (collection.contains(it3.next())) {
                it3.remove();
                zRemove = true;
            }
        }
        return zRemove;
    }
}
