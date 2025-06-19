package androidx.compose.ui.node;

import com.google.android.gms.internal.mlkit_vision_barcode.W4;

/* renamed from: androidx.compose.ui.node.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0911g implements androidx.compose.ui.focus.k {
    public static final C0911g a = new C0911g();
    public static Boolean b;

    @Override // androidx.compose.ui.focus.k
    public final boolean b() {
        Boolean bool = b;
        if (bool != null) {
            return bool.booleanValue();
        }
        W4.g("canFocus is read before it is written");
        throw null;
    }

    @Override // androidx.compose.ui.focus.k
    public final void d(boolean z) {
        b = Boolean.valueOf(z);
    }
}
