package androidx.appcompat.widget;

import android.text.StaticLayout;
import android.widget.TextView;

/* renamed from: androidx.appcompat.widget.g0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0086g0 {
    public abstract void a(StaticLayout.Builder builder, TextView textView);

    public boolean b(TextView textView) {
        return ((Boolean) C0088h0.e("getHorizontallyScrolling", textView, Boolean.FALSE)).booleanValue();
    }
}
