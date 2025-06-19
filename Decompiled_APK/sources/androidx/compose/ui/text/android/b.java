package androidx.compose.ui.text.android;

import android.graphics.RectF;
import android.text.Layout;
import android.text.SegmentFinder;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class b {
    public static final b a = new b();

    /* JADX WARN: Type inference failed for: r0v2, types: [androidx.compose.ui.text.android.a] */
    public final int[] a(@NotNull x xVar, @NotNull RectF rectF, int i, @NotNull final Function2<? super RectF, ? super RectF, Boolean> function2) {
        SegmentFinder segmentFinderP;
        if (i == 1) {
            segmentFinderP = androidx.compose.ui.text.android.selection.b.a.a(new com.quizlet.data.interactor.school.b(4, xVar.e.getText(), xVar.j()));
        } else {
            androidx.compose.foundation.text.input.internal.p.w();
            segmentFinderP = androidx.compose.foundation.text.input.internal.p.p(androidx.compose.foundation.text.input.internal.p.o(xVar.e.getText(), xVar.a));
        }
        return xVar.e.getRangeForRect(rectF, segmentFinderP, new Layout.TextInclusionStrategy() { // from class: androidx.compose.ui.text.android.a
            @Override // android.text.Layout.TextInclusionStrategy
            public final boolean isSegmentInside(RectF rectF2, RectF rectF3) {
                return ((Boolean) function2.invoke(rectF2, rectF3)).booleanValue();
            }
        });
    }
}
