package com.google.android.gms.internal.mlkit_vision_camera;

import assistantMode.types.C1454a;
import java.util.AbstractCollection;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;
import org.wordpress.aztec.EnumC5145a;

/* loaded from: classes2.dex */
public abstract class X2 {
    public static final void a(ArrayList arrayList, AbstractCollection abstractCollection, Integer num) {
        Iterator it2 = ((ArrayList) kotlin.collections.A.c(abstractCollection)).iterator();
        while (it2.hasNext()) {
            C1454a c1454a = (C1454a) it2.next();
            if (num != null && arrayList.size() >= num.intValue()) {
                return;
            }
            if (!arrayList.contains(c1454a)) {
                arrayList.add(c1454a);
            }
        }
    }

    public static final org.wordpress.aztec.spans.T b(int i, EnumC5145a alignmentRendering, C5146b attributes, org.wordpress.aztec.formatting.f paragraphStyle) {
        Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(paragraphStyle, "paragraphStyle");
        int iOrdinal = alignmentRendering.ordinal();
        if (iOrdinal == 0) {
            return new org.wordpress.aztec.spans.U(i, attributes, null, paragraphStyle);
        }
        if (iOrdinal == 1) {
            return new org.wordpress.aztec.spans.T(i, attributes, paragraphStyle);
        }
        throw new NoWhenBranchMatchedException();
    }
}
