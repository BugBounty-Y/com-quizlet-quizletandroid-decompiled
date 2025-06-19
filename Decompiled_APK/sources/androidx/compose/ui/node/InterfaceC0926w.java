package androidx.compose.ui.node;

import androidx.compose.ui.layout.C0890k;
import androidx.compose.ui.layout.C0896q;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;

/* renamed from: androidx.compose.ui.node.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public interface InterfaceC0926w extends InterfaceC0917m {
    default int b(O o, androidx.compose.ui.layout.J j, int i) {
        return h(new C0896q(o, o.getLayoutDirection()), new C0890k(j, 2, 1, 2), L5.b(0, i, 7)).getWidth();
    }

    default int c(O o, androidx.compose.ui.layout.J j, int i) {
        int i2 = 1;
        return h(new C0896q(o, o.getLayoutDirection()), new C0890k(j, i2, i2, 2), L5.b(0, i, 7)).getWidth();
    }

    default int f(O o, androidx.compose.ui.layout.J j, int i) {
        return h(new C0896q(o, o.getLayoutDirection()), new C0890k(j, 1, 2, 2), L5.b(i, 0, 13)).b();
    }

    androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2);

    default int i(O o, androidx.compose.ui.layout.J j, int i) {
        int i2 = 2;
        return h(new C0896q(o, o.getLayoutDirection()), new C0890k(j, i2, i2, 2), L5.b(i, 0, 13)).b();
    }
}
