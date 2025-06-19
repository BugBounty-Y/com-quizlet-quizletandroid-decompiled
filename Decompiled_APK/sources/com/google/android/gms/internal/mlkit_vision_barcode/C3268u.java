package com.google.android.gms.internal.mlkit_vision_barcode;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3502n4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3531s4;
import java.util.Arrays;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.u, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3268u {
    public Object[] a;
    public int b;
    public boolean c;

    public C3268u(int i) {
        switch (i) {
            case 1:
                this.a = new Object[4];
                this.b = 0;
                break;
            case 2:
                AbstractC3502n4.i(4, "initialCapacity");
                this.a = new Object[4];
                this.b = 0;
                break;
            default:
                this.a = new Object[4];
                this.b = 0;
                break;
        }
    }

    public static int d(int i, int i2) {
        if (i2 < 0) {
            throw new IllegalArgumentException("cannot store more than Integer.MAX_VALUE elements");
        }
        if (i2 <= i) {
            return i;
        }
        int iHighestOneBit = i + (i >> 1) + 1;
        if (iHighestOneBit < i2) {
            iHighestOneBit = Integer.highestOneBit(i2 - 1) << 1;
        }
        return iHighestOneBit < 0 ? SubsamplingScaleImageView.TILE_SIZE_AUTO : iHighestOneBit;
    }

    public void a(Object obj) {
        obj.getClass();
        c(1);
        Object[] objArr = this.a;
        int i = this.b;
        this.b = i + 1;
        objArr[i] = obj;
    }

    public void b(Object... objArr) {
        int length = objArr.length;
        AbstractC3531s4.e(length, objArr);
        c(length);
        System.arraycopy(objArr, 0, this.a, this.b, length);
        this.b += length;
    }

    public void c(int i) {
        Object[] objArr = this.a;
        int iD = d(objArr.length, this.b + i);
        if (iD > objArr.length || this.c) {
            this.a = Arrays.copyOf(this.a, iD);
            this.c = false;
        }
    }

    public void e(Object obj) {
        int i = this.b;
        int i2 = i + 1;
        Object[] objArr = this.a;
        int length = objArr.length;
        if (length < i2) {
            int i3 = length + (length >> 1) + 1;
            if (i3 < i2) {
                int iHighestOneBit = Integer.highestOneBit(i);
                i3 = iHighestOneBit + iHighestOneBit;
            }
            if (i3 < 0) {
                i3 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
            }
            this.a = Arrays.copyOf(objArr, i3);
            this.c = false;
        } else if (this.c) {
            this.a = (Object[]) objArr.clone();
            this.c = false;
        }
        Object[] objArr2 = this.a;
        int i4 = this.b;
        this.b = i4 + 1;
        objArr2[i4] = obj;
    }

    public void f(Object obj) {
        obj.getClass();
        g(this.b + 1);
        Object[] objArr = this.a;
        int i = this.b;
        this.b = i + 1;
        objArr[i] = obj;
    }

    public void g(int i) {
        Object[] objArr = this.a;
        int length = objArr.length;
        if (length >= i) {
            if (this.c) {
                this.a = (Object[]) objArr.clone();
                this.c = false;
                return;
            }
            return;
        }
        int i2 = length + (length >> 1) + 1;
        if (i2 < i) {
            int iHighestOneBit = Integer.highestOneBit(i - 1);
            i2 = iHighestOneBit + iHighestOneBit;
        }
        if (i2 < 0) {
            i2 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        }
        this.a = Arrays.copyOf(objArr, i2);
        this.c = false;
    }

    public B h() {
        this.c = true;
        Object[] objArr = this.a;
        int i = this.b;
        C3276v c3276v = AbstractC3292x.b;
        return i == 0 ? B.e : new B(objArr, i);
    }
}
