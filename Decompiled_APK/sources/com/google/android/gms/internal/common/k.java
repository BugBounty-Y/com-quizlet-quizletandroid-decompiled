package com.google.android.gms.internal.common;

import androidx.appcompat.app.K;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3524r3;
import java.util.Iterator;
import java.util.NoSuchElementException;

/* loaded from: classes2.dex */
public final class k implements Iterator {
    public String a;
    public final String c;
    public final boolean d;
    public final /* synthetic */ j g;
    public int b = 2;
    public int e = 0;
    public int f = SubsamplingScaleImageView.TILE_SIZE_AUTO;

    public k(K k, String str, j jVar) {
        this.g = jVar;
        this.d = k.a;
        this.c = str;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        int length;
        String str;
        int i;
        int i2 = this.b;
        if (i2 == 4) {
            throw new IllegalStateException();
        }
        int i3 = i2 - 1;
        String string = null;
        if (i2 == 0) {
            throw null;
        }
        if (i3 == 0) {
            return true;
        }
        if (i3 != 2) {
            this.b = 4;
            int i4 = this.e;
            while (true) {
                length = this.e;
                if (length == -1) {
                    this.b = 3;
                    break;
                }
                str = this.c;
                int length2 = str.length();
                AbstractC3524r3.c(length, length2);
                while (true) {
                    if (length >= length2) {
                        length = -1;
                        break;
                    }
                    if (str.charAt(length) == this.g.a) {
                        break;
                    }
                    length++;
                }
                if (length == -1) {
                    length = str.length();
                    this.e = -1;
                    i = -1;
                } else {
                    i = length + 1;
                    this.e = i;
                }
                if (i == i4) {
                    int i5 = i + 1;
                    this.e = i5;
                    if (i5 > str.length()) {
                        this.e = -1;
                    }
                } else {
                    if (i4 < length) {
                        str.charAt(i4);
                    }
                    if (i4 < length) {
                        str.charAt(length - 1);
                    }
                    if (!this.d || i4 != length) {
                        break;
                    }
                    i4 = this.e;
                }
            }
            int i6 = this.f;
            if (i6 == 1) {
                length = str.length();
                this.e = -1;
                if (length > i4) {
                    str.charAt(length - 1);
                }
            } else {
                this.f = i6 - 1;
            }
            string = str.subSequence(i4, length).toString();
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
