package com.quizlet.local.datastore.preferences;

import androidx.datastore.core.InterfaceC1076h;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import kotlin.collections.AbstractC4916g;
import kotlin.collections.C4913d;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;

/* renamed from: com.quizlet.local.datastore.preferences.z, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4589z {
    public final InterfaceC1076h a;

    public C4589z(InterfaceC1076h dataStore) {
        Intrinsics.checkNotNullParameter(dataStore, "dataStore");
        this.a = dataStore;
    }

    public static String a(com.quizlet.data.model.V v) {
        int i;
        kotlin.io.encoding.a aVar = kotlin.io.encoding.c.c;
        String[] elements = {v.a, v.b, v.c, v.d};
        Intrinsics.checkNotNullParameter(elements, "elements");
        byte[] source = CollectionsKt.S(C4933y.z(elements), ":", null, null, null, 62).getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(source, "getBytes(...)");
        int length = source.length;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(source, "source");
        int length2 = source.length;
        C4913d c4913d = AbstractC4916g.a;
        c4913d.getClass();
        C4913d.a(0, length, length2);
        int iB = aVar.b(length);
        byte[] destination = new byte[iB];
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(destination, "destination");
        int length3 = source.length;
        c4913d.getClass();
        C4913d.a(0, length, length3);
        int iB2 = aVar.b(length);
        if (iB < 0) {
            throw new IndexOutOfBoundsException(android.support.v4.media.session.a.f(iB, "destination offset: 0, destination size: "));
        }
        if (iB2 < 0 || iB2 > iB) {
            throw new IndexOutOfBoundsException(androidx.compose.animation.d0.p("The destination array does not have enough capacity, destination offset: 0, destination size: ", iB, ", capacity needed: ", iB2));
        }
        byte[] bArr = aVar.a ? kotlin.io.encoding.d.c : kotlin.io.encoding.d.a;
        int i2 = aVar.b ? 19 : SubsamplingScaleImageView.TILE_SIZE_AUTO;
        int i3 = 0;
        int i4 = 0;
        while (true) {
            i = i3 + 2;
            if (i >= length) {
                break;
            }
            int iMin = Math.min((length - i3) / 3, i2);
            for (int i5 = 0; i5 < iMin; i5++) {
                int i6 = source[i3] & 255;
                int i7 = i3 + 2;
                int i8 = source[i3 + 1] & 255;
                i3 += 3;
                int i9 = (i8 << 8) | (i6 << 16) | (source[i7] & 255);
                destination[i4] = bArr[i9 >>> 18];
                destination[i4 + 1] = bArr[(i9 >>> 12) & 63];
                int i10 = i4 + 3;
                destination[i4 + 2] = bArr[(i9 >>> 6) & 63];
                i4 += 4;
                destination[i10] = bArr[i9 & 63];
            }
            if (iMin == i2 && i3 != length) {
                int i11 = i4 + 1;
                byte[] bArr2 = kotlin.io.encoding.c.d;
                destination[i4] = bArr2[0];
                i4 += 2;
                destination[i11] = bArr2[1];
            }
        }
        int i12 = length - i3;
        if (i12 == 1) {
            int i13 = (source[i3] & 255) << 4;
            destination[i4] = bArr[i13 >>> 6];
            destination[1 + i4] = bArr[i13 & 63];
            kotlin.io.encoding.b[] bVarArr = kotlin.io.encoding.b.a;
            destination[2 + i4] = 61;
            destination[i4 + 3] = 61;
            i3++;
        } else if (i12 == 2) {
            int i14 = ((source[i3 + 1] & 255) << 2) | ((source[i3] & 255) << 10);
            destination[i4] = bArr[i14 >>> 12];
            destination[1 + i4] = bArr[(i14 >>> 6) & 63];
            destination[2 + i4] = bArr[i14 & 63];
            kotlin.io.encoding.b[] bVarArr2 = kotlin.io.encoding.b.a;
            destination[i4 + 3] = 61;
            i3 = i;
        }
        if (i3 == length) {
            return new String(destination, Charsets.c);
        }
        throw new IllegalStateException("Check failed.");
    }
}
