package com.google.android.gms.internal.mlkit_vision_document_scanner;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class T3 {
    public static final T3 c = new T3(false, AbstractC3588c.h(0, new Object[4]));
    public static final T3 d;
    public final boolean a;
    public final C3604e b;

    static {
        Object[] objArrCopyOf = new Object[4];
        S1 s1 = new S1();
        boolean z = true;
        int i = 0 + 1;
        int length = objArrCopyOf.length;
        if (length < i) {
            int i2 = length + (length >> 1) + 1;
            if (i2 < i) {
                int iHighestOneBit = Integer.highestOneBit(0);
                i2 = iHighestOneBit + iHighestOneBit;
            }
            if (i2 < 0) {
                i2 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
            }
            objArrCopyOf = Arrays.copyOf(objArrCopyOf, i2);
        }
        objArrCopyOf[0] = s1;
        AbstractC3588c.h(0 + 1, objArrCopyOf);
        d = new T3(z, AbstractC3588c.h(0, new Object[4]));
    }

    public /* synthetic */ T3(boolean z, C3604e c3604e) {
        this.a = z;
        this.b = c3604e;
    }
}
