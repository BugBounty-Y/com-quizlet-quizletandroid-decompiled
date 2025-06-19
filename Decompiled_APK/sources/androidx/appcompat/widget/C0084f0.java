package androidx.appcompat.widget;

import android.text.StaticLayout;
import android.widget.TextView;

/* renamed from: androidx.appcompat.widget.f0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0084f0 extends C0082e0 {
    @Override // androidx.appcompat.widget.C0082e0, androidx.appcompat.widget.AbstractC0086g0
    public void a(StaticLayout.Builder builder, TextView textView) {
        builder.setTextDirection(textView.getTextDirectionHeuristic());
    }

    @Override // androidx.appcompat.widget.AbstractC0086g0
    public boolean b(TextView textView) {
        return textView.isHorizontallyScrollable();
    }
}
