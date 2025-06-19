package androidx.compose.ui.text.android.selection;

import android.content.res.TypedArray;
import android.os.RemoteException;
import android.util.SparseArray;
import androidx.compose.animation.d0;
import androidx.compose.runtime.changelist.K;
import androidx.compose.ui.text.android.j;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.Ds;
import com.google.android.gms.internal.ads.Fs;
import com.google.android.gms.internal.ads.J1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3232p5;
import com.google.android.material.textfield.l;
import java.text.BreakIterator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Locale;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class f {
    public final /* synthetic */ int a;
    public int b;
    public int c;
    public Object d;
    public Object e;

    public f(int i, ArrayList arrayList, int i2, com.android.volley.toolbox.e eVar) {
        this.a = 3;
        this.b = i;
        this.d = arrayList;
        this.c = i2;
        this.e = eVar;
    }

    public void a(int i) {
        if (this.b == -1) {
            this.b = i;
            this.c = i;
            return;
        }
        int[] iArr = (int[]) this.d;
        int i2 = this.c;
        iArr[i2] = i;
        ((int[]) this.e)[i] = i2;
        this.c = i;
    }

    public void b(int i) {
        int i2 = this.b;
        int i3 = this.c;
        if (i > i3 || i2 > i) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.q(android.support.v4.media.session.a.w("Invalid offset: ", i, ". Valid range is [", " , ", i2), i3, ']').toString());
        }
    }

    public Object[] c() {
        return null;
    }

    public int d() {
        K k = (K) this.e;
        if (k == null) {
            return ((String) this.d).length();
        }
        return (k.b - k.c()) + (((String) this.d).length() - (this.c - this.b));
    }

    public void e(int i) {
        this.b = -1;
        this.c = -1;
        int[] iArr = new int[i];
        for (int i2 = 0; i2 < i; i2++) {
            iArr[i2] = -1;
        }
        this.d = iArr;
        int[] iArr2 = new int[i];
        for (int i3 = 0; i3 < i; i3++) {
            iArr2[i3] = -1;
        }
        this.e = iArr2;
    }

    public boolean f(int i) {
        return i <= this.c && this.b + 1 <= i && Character.isLetterOrDigit(Character.codePointBefore((CharSequence) this.d, i));
    }

    public boolean g(int i) {
        int i2 = this.b + 1;
        if (i > this.c || i2 > i) {
            return false;
        }
        return AbstractC3232p5.b(Character.codePointBefore((CharSequence) this.d, i));
    }

    public boolean h(int i) {
        return i < this.c && this.b <= i && Character.isLetterOrDigit(Character.codePointAt((CharSequence) this.d, i));
    }

    public boolean i(int i) {
        if (i >= this.c || this.b > i) {
            return false;
        }
        return AbstractC3232p5.b(Character.codePointAt((CharSequence) this.d, i));
    }

    public void j(int i, int i2, int i3, int i4) {
        if (i < 0) {
            int i5 = this.b;
            i += i5;
            i2 += 4 - ((i5 + 4) % 8);
        }
        int i6 = this.c;
        if (i2 < 0) {
            i2 += i6;
            i += 4 - ((i6 + 4) % 8);
        }
        ((byte[]) this.e)[(i * i6) + i2] = (byte) ((((String) this.d).charAt(i3) & (1 << (8 - i4))) == 0 ? 0 : 1);
    }

    public void k(int i) {
        int i2 = this.c;
        if (i == i2) {
            return;
        }
        int[] iArr = (int[]) this.e;
        int i3 = iArr[i];
        int[] iArr2 = (int[]) this.d;
        int i4 = iArr2[i];
        if (i == this.b) {
            this.b = i4;
        }
        if (i3 != -1) {
            iArr2[i3] = i4;
        }
        if (i4 != -1) {
            iArr[i4] = i3;
        }
        iArr2[i2] = i;
        iArr[i] = i2;
        iArr2[i] = -1;
        this.c = i;
    }

    public void l(int i) {
        if (i == this.b) {
            this.b = ((int[]) this.d)[i];
        }
        if (i == this.c) {
            this.c = ((int[]) this.e)[i];
        }
        int[] iArr = (int[]) this.e;
        int i2 = iArr[i];
        int[] iArr2 = (int[]) this.d;
        int i3 = iArr2[i];
        if (i2 != -1) {
            iArr2[i2] = i3;
        }
        if (i3 != -1) {
            iArr[i3] = i2;
        }
        iArr2[i] = -1;
        iArr[i] = -1;
    }

    public void m(int i, int i2, String str) {
        if (i > i2) {
            throw new IllegalArgumentException(d0.p("start index must be less than or equal to end index: ", i, " > ", i2).toString());
        }
        if (i < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "start must be non-negative, but was ").toString());
        }
        K k = (K) this.e;
        if (k == null) {
            int iMax = Math.max(255, str.length() + 128);
            char[] cArr = new char[iMax];
            int iMin = Math.min(i, 64);
            int iMin2 = Math.min(((String) this.d).length() - i2, 64);
            String str2 = (String) this.d;
            int i3 = i - iMin;
            Intrinsics.e(str2, "null cannot be cast to non-null type java.lang.String");
            str2.getChars(i3, i, cArr, 0);
            String str3 = (String) this.d;
            int i4 = iMax - iMin2;
            int i5 = iMin2 + i2;
            Intrinsics.e(str3, "null cannot be cast to non-null type java.lang.String");
            str3.getChars(i2, i5, cArr, i4);
            str.getChars(0, str.length(), cArr, iMin);
            int length = str.length() + iMin;
            K k2 = new K(1, (byte) 0);
            k2.b = iMax;
            k2.e = cArr;
            k2.c = length;
            k2.d = i4;
            this.e = k2;
            this.b = i3;
            this.c = i5;
            return;
        }
        int i6 = this.b;
        int i7 = i - i6;
        int i8 = i2 - i6;
        if (i7 < 0 || i8 > k.b - k.c()) {
            this.d = toString();
            this.e = null;
            this.b = -1;
            this.c = -1;
            m(i, i2, str);
            return;
        }
        int length2 = str.length() - (i8 - i7);
        if (length2 > k.c()) {
            int iC = length2 - k.c();
            int i9 = k.b;
            do {
                i9 *= 2;
            } while (i9 - k.b < iC);
            char[] cArr2 = new char[i9];
            C4930v.f((char[]) k.e, cArr2, 0, 0, k.c);
            int i10 = k.b;
            int i11 = k.d;
            int i12 = i10 - i11;
            int i13 = i9 - i12;
            C4930v.f((char[]) k.e, cArr2, i13, i11, i12 + i11);
            k.e = cArr2;
            k.b = i9;
            k.d = i13;
        }
        int i14 = k.c;
        if (i7 < i14 && i8 <= i14) {
            int i15 = i14 - i8;
            char[] cArr3 = (char[]) k.e;
            C4930v.f(cArr3, cArr3, k.d - i15, i8, i14);
            k.c = i7;
            k.d -= i15;
        } else if (i7 >= i14 || i8 < i14) {
            int iC2 = k.c() + i7;
            int iC3 = k.c() + i8;
            int i16 = k.d;
            char[] cArr4 = (char[]) k.e;
            C4930v.f(cArr4, cArr4, k.c, i16, iC2);
            k.c += iC2 - i16;
            k.d = iC3;
        } else {
            k.d = k.c() + i8;
            k.c = i7;
        }
        str.getChars(0, str.length(), (char[]) k.e, k.c);
        k.c = str.length() + k.c;
    }

    public void n(int i, int i2, int i3) {
        int i4 = i - 2;
        int i5 = i2 - 2;
        j(i4, i5, i3, 1);
        int i6 = i2 - 1;
        j(i4, i6, i3, 2);
        int i7 = i - 1;
        j(i7, i5, i3, 3);
        j(i7, i6, i3, 4);
        j(i7, i2, i3, 5);
        j(i, i5, i3, 6);
        j(i, i6, i3, 7);
        j(i, i2, i3, 8);
    }

    public synchronized int o() {
        return this.c;
    }

    public synchronized Object p() {
        if (this.c == 0) {
            return null;
        }
        return t();
    }

    public synchronized Object q(long j) {
        Object objT;
        objT = null;
        while (this.c > 0 && j - ((long[]) this.d)[this.b] >= 0) {
            objT = t();
        }
        return objT;
    }

    public synchronized void r() {
        try {
            Ds ds = (Ds) this.e;
            if (ds.b) {
                Fs fs = ds.a;
                fs.B1((byte[]) this.d);
                fs.s2(this.b);
                fs.e(this.c);
                fs.o0();
                fs.f();
            }
        } catch (RemoteException unused) {
        }
    }

    public synchronized void s(long j, Object obj) {
        try {
            if (this.c > 0) {
                if (j <= ((long[]) this.d)[((this.b + r0) - 1) % ((Object[]) this.e).length]) {
                    synchronized (this) {
                        this.b = 0;
                        this.c = 0;
                        Arrays.fill((Object[]) this.e, (Object) null);
                    }
                }
            }
            int length = ((Object[]) this.e).length;
            if (this.c >= length) {
                int i = length + length;
                long[] jArr = new long[i];
                Object[] objArr = new Object[i];
                int i2 = this.b;
                int i3 = length - i2;
                System.arraycopy((long[]) this.d, i2, jArr, 0, i3);
                System.arraycopy((Object[]) this.e, this.b, objArr, 0, i3);
                int i4 = this.b;
                if (i4 > 0) {
                    System.arraycopy((long[]) this.d, 0, jArr, i3, i4);
                    System.arraycopy((Object[]) this.e, 0, objArr, i3, this.b);
                }
                this.d = jArr;
                this.e = objArr;
                this.b = 0;
            }
            int i5 = this.b;
            int i6 = this.c;
            Object[] objArr2 = (Object[]) this.e;
            int length2 = (i5 + i6) % objArr2.length;
            ((long[]) this.d)[length2] = j;
            objArr2[length2] = obj;
            this.c = i6 + 1;
        } catch (Throwable th) {
            throw th;
        }
    }

    public Object t() {
        AbstractC1795We.L(this.c > 0);
        Object[] objArr = (Object[]) this.e;
        int i = this.b;
        Object obj = objArr[i];
        objArr[i] = null;
        this.b = (i + 1) % objArr.length;
        this.c--;
        return obj;
    }

    public String toString() {
        switch (this.a) {
            case 1:
                K k = (K) this.e;
                if (k == null) {
                    return (String) this.d;
                }
                StringBuilder sb = new StringBuilder();
                sb.append((CharSequence) this.d, 0, this.b);
                sb.append((char[]) k.e, 0, k.c);
                Intrinsics.checkNotNullExpressionValue(sb, "this.append(value, start…x, endIndex - startIndex)");
                char[] cArr = (char[]) k.e;
                int i = k.d;
                sb.append(cArr, i, k.b - i);
                Intrinsics.checkNotNullExpressionValue(sb, "this.append(value, start…x, endIndex - startIndex)");
                String str = (String) this.d;
                sb.append((CharSequence) str, this.c, str.length());
                return sb.toString();
            default:
                return super.toString();
        }
    }

    public /* synthetic */ f(Ds ds, byte[] bArr) {
        this.a = 5;
        this.e = ds;
        this.d = bArr;
    }

    public f(int i) {
        this.a = 2;
        this.d = new J1[i];
        this.c = 0;
    }

    public f(int i, byte b) {
        this.a = i;
        switch (i) {
            case 4:
                this.d = new long[10];
                this.e = new Object[10];
                break;
            case 8:
                this.b = -1;
                this.c = -1;
                int[] iArr = com.mayakapps.kache.collection.internal.a.a;
                this.d = iArr;
                this.e = iArr;
                break;
        }
    }

    public f(CharSequence charSequence, int i, Locale locale) {
        this.a = 0;
        this.d = charSequence;
        if (charSequence.length() >= 0) {
            if (i >= 0 && i <= charSequence.length()) {
                BreakIterator wordInstance = BreakIterator.getWordInstance(locale);
                this.e = wordInstance;
                this.b = Math.max(0, -50);
                this.c = Math.min(charSequence.length(), i + 50);
                wordInstance.setText(new j(i, charSequence));
                return;
            }
            throw new IllegalArgumentException("input end index is outside the CharSequence");
        }
        throw new IllegalArgumentException("input start index is outside the CharSequence");
    }

    public f(String str, int i, int i2) {
        this.a = 7;
        this.d = str;
        this.c = i;
        this.b = i2;
        byte[] bArr = new byte[i * i2];
        this.e = bArr;
        Arrays.fill(bArr, (byte) -1);
    }

    public f(l lVar, com.quizlet.data.repository.classfolder.e eVar) {
        this.a = 6;
        this.d = new SparseArray();
        this.e = lVar;
        TypedArray typedArray = (TypedArray) eVar.c;
        this.b = typedArray.getResourceId(28, 0);
        this.c = typedArray.getResourceId(52, 0);
    }
}
