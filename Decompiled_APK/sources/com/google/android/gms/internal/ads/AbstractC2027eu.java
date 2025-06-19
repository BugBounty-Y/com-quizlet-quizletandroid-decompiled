package com.google.android.gms.internal.ads;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.common.Feature;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

/* renamed from: com.google.android.gms.internal.ads.eu, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2027eu {
    public final /* synthetic */ int a;
    public Object[] b;
    public int c;
    public boolean d;

    public AbstractC2027eu(int i) {
        this.a = 0;
        AbstractC2543qs.g(i, "initialCapacity");
        this.b = new Object[i];
        this.c = 0;
    }

    public static com.google.android.gms.common.api.internal.k a() {
        com.google.android.gms.common.api.internal.k kVar = new com.google.android.gms.common.api.internal.k();
        kVar.c = true;
        kVar.b = 0;
        return kVar;
    }

    public static int e(int i, int i2) {
        if (i2 < 0) {
            throw new IllegalArgumentException("cannot store more than MAX_VALUE elements");
        }
        if (i2 <= i) {
            return i;
        }
        int i3 = i + (i >> 1) + 1;
        if (i3 < i2) {
            int iHighestOneBit = Integer.highestOneBit(i2 - 1);
            i3 = iHighestOneBit + iHighestOneBit;
        }
        return i3 < 0 ? SubsamplingScaleImageView.TILE_SIZE_AUTO : i3;
    }

    public static int h(int i, int i2) {
        if (i2 < 0) {
            throw new IllegalArgumentException("cannot store more than Integer.MAX_VALUE elements");
        }
        if (i2 <= i) {
            return i;
        }
        int i3 = i + (i >> 1) + 1;
        if (i3 < i2) {
            int iHighestOneBit = Integer.highestOneBit(i2 - 1);
            i3 = iHighestOneBit + iHighestOneBit;
        }
        return i3 < 0 ? SubsamplingScaleImageView.TILE_SIZE_AUTO : i3;
    }

    public abstract void b(com.google.android.gms.common.api.c cVar, com.google.android.gms.tasks.f fVar);

    public void c(Object obj) {
        switch (this.a) {
            case 0:
                obj.getClass();
                i(1);
                Object[] objArr = this.b;
                int i = this.c;
                this.c = i + 1;
                objArr[i] = obj;
                break;
            default:
                obj.getClass();
                g(1);
                Object[] objArr2 = this.b;
                int i2 = this.c;
                this.c = i2 + 1;
                objArr2[i2] = obj;
                break;
        }
    }

    public abstract AbstractC2027eu d(Object obj);

    public void f(Iterable iterable) {
        if (iterable instanceof Collection) {
            Collection collection = (Collection) iterable;
            i(collection.size());
            if (collection instanceof AbstractC2071fu) {
                this.c = ((AbstractC2071fu) collection).a(this.b, this.c);
                return;
            }
        }
        Iterator it2 = iterable.iterator();
        while (it2.hasNext()) {
            d(it2.next());
        }
    }

    public void g(int i) {
        int length = this.b.length;
        int iE = e(length, this.c + i);
        if (iE > length || this.d) {
            this.b = Arrays.copyOf(this.b, iE);
            this.d = false;
        }
    }

    public void i(int i) {
        int length = this.b.length;
        int iH = h(length, this.c + i);
        if (iH > length || this.d) {
            this.b = Arrays.copyOf(this.b, iH);
            this.d = false;
        }
    }

    public AbstractC2027eu(int i, byte b) {
        this.a = i;
        switch (i) {
            case 2:
                this.b = null;
                this.d = false;
                this.c = 0;
                break;
            default:
                com.google.android.gms.internal.play_billing.Z0.i(4, "initialCapacity");
                this.b = new Object[4];
                this.c = 0;
                break;
        }
    }

    public AbstractC2027eu(Feature[] featureArr, boolean z, int i) {
        this.a = 2;
        this.b = featureArr;
        boolean z2 = false;
        if (featureArr != null && z) {
            z2 = true;
        }
        this.d = z2;
        this.c = i;
    }
}
