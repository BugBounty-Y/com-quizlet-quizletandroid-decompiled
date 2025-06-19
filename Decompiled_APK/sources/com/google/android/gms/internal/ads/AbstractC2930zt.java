package com.google.android.gms.internal.ads;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.Iterator;
import java.util.NoSuchElementException;

/* renamed from: com.google.android.gms.internal.ads.zt, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2930zt implements Iterator {
    public String a;
    public final CharSequence c;
    public int b = 2;
    public int d = 0;
    public int e = SubsamplingScaleImageView.TILE_SIZE_AUTO;

    public AbstractC2930zt(CharSequence charSequence) {
        this.c = charSequence;
    }

    public abstract int a(int i);

    public abstract int b(int i);

    @Override // java.util.Iterator
    public final boolean hasNext() {
        int iA;
        int i = this.b;
        if (i == 4) {
            throw new IllegalStateException();
        }
        int i2 = i - 1;
        String string = null;
        if (i == 0) {
            throw null;
        }
        if (i2 == 0) {
            return true;
        }
        if (i2 != 2) {
            this.b = 4;
            int i3 = this.d;
            while (true) {
                int i4 = this.d;
                if (i4 == -1) {
                    this.b = 3;
                    break;
                }
                int iB = b(i4);
                CharSequence charSequence = this.c;
                if (iB == -1) {
                    iB = charSequence.length();
                    this.d = -1;
                    iA = -1;
                } else {
                    iA = a(iB);
                    this.d = iA;
                }
                if (iA == i3) {
                    int i5 = iA + 1;
                    this.d = i5;
                    if (i5 > charSequence.length()) {
                        this.d = -1;
                    }
                } else {
                    if (i3 < iB) {
                        charSequence.charAt(i3);
                    }
                    if (i3 < iB) {
                        charSequence.charAt(iB - 1);
                    }
                    int i6 = this.e;
                    if (i6 == 1) {
                        iB = charSequence.length();
                        this.d = -1;
                        if (iB > i3) {
                            charSequence.charAt(iB - 1);
                        }
                    } else {
                        this.e = i6 - 1;
                    }
                    string = charSequence.subSequence(i3, iB).toString();
                }
            }
            this.a = string;
            if (this.b != 3) {
                this.b = 1;
                return true;
            }
        }
        return false;
    }

    @Override // java.util.Iterator
    public final Object next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        this.b = 2;
        String str = this.a;
        this.a = null;
        return str;
    }

    @Override // java.util.Iterator
    public final void remove() {
        throw new UnsupportedOperationException();
    }
}
