package androidx.core.view;

import android.os.Build;
import androidx.core.widget.NestedScrollView;

/* renamed from: androidx.core.view.y, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1067y {
    public final InterfaceC1066x a;

    public C1067y(NestedScrollView nestedScrollView) {
        if (Build.VERSION.SDK_INT >= 35) {
            this.a = new C1065w(nestedScrollView);
        } else {
            this.a = new com.google.mlkit.common.sdkinternal.b(3);
        }
    }
}
