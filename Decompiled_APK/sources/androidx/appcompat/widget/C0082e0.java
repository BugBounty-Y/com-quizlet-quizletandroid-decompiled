package androidx.appcompat.widget;

import android.text.StaticLayout;
import android.text.TextDirectionHeuristic;
import android.text.TextDirectionHeuristics;
import android.widget.TextView;

/* renamed from: androidx.appcompat.widget.e0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C0082e0 extends AbstractC0086g0 {
    @Override // androidx.appcompat.widget.AbstractC0086g0
    public void a(StaticLayout.Builder builder, TextView textView) {
        builder.setTextDirection((TextDirectionHeuristic) C0088h0.e("getTextDirectionHeuristic", textView, TextDirectionHeuristics.FIRSTSTRONG_LTR));
    }
}
