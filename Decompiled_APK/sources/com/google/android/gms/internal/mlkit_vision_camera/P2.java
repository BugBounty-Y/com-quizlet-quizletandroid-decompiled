package com.google.android.gms.internal.mlkit_vision_camera;

import assistantMode.types.C1454a;
import assistantMode.types.C1457d;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;
import org.wordpress.aztec.EnumC5145a;
import org.wordpress.aztec.spans.AztecPreformatSpan;
import org.wordpress.aztec.spans.AztecPreformatSpanAligned;

/* loaded from: classes2.dex */
public abstract class P2 {
    public static final /* synthetic */ int a = 0;

    public static final AztecPreformatSpan a(int i, EnumC5145a alignmentRendering, C5146b attributes, org.wordpress.aztec.formatting.g preformatStyle) {
        Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(preformatStyle, "preformatStyle");
        int iOrdinal = alignmentRendering.ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                return new AztecPreformatSpan(i, attributes, preformatStyle);
            }
            throw new NoWhenBranchMatchedException();
        }
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(preformatStyle, "preformatStyle");
        AztecPreformatSpanAligned aztecPreformatSpanAligned = new AztecPreformatSpanAligned(i, attributes, preformatStyle);
        aztecPreformatSpanAligned.n = i;
        aztecPreformatSpanAligned.o = attributes;
        aztecPreformatSpanAligned.p = preformatStyle;
        aztecPreformatSpanAligned.q = null;
        return aztecPreformatSpanAligned;
    }

    public static final assistantMode.grading.p b(Q2 q2, assistantMode.types.B questionConfig, assistantMode.utils.h studyableMaterialDataSource) {
        assistantMode.enums.m mVar;
        Intrinsics.checkNotNullParameter(q2, "<this>");
        Intrinsics.checkNotNullParameter(questionConfig, "questionConfig");
        Intrinsics.checkNotNullParameter(studyableMaterialDataSource, "studyableMaterialDataSource");
        C1454a c1454a = (C1454a) CollectionsKt.L(questionConfig.a());
        C1457d c1457d = questionConfig.a;
        assistantMode.enums.m mVar2 = c1457d.b;
        List listC = studyableMaterialDataSource.c(c1454a, mVar2);
        ArrayList arrayList = new ArrayList();
        for (Object obj : listC) {
            if (!Intrinsics.b((C1454a) obj, c1454a)) {
                arrayList.add(obj);
            }
        }
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            mVar = c1457d.c;
            if (!zHasNext) {
                break;
            }
            arrayList2.add(((C1454a) it2.next()).i(mVar).e());
        }
        k3 k3VarI = assistantMode.utils.g.f(mVar2) ? c1454a.i(mVar2) : null;
        return new assistantMode.grading.p(c1454a.i(mVar).e(), N2.c(c1454a, mVar), arrayList2, k3VarI != null ? k3VarI.e() : null, k3VarI != null ? k3VarI.c() : null, c1454a.i(mVar).c());
    }
}
