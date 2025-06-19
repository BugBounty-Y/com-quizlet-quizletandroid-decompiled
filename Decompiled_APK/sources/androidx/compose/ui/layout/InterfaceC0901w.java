package androidx.compose.ui.layout;

import com.google.android.gms.internal.mlkit_vision_barcode.L5;

/* renamed from: androidx.compose.ui.layout.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public interface InterfaceC0901w extends androidx.compose.ui.o {
    default int b(androidx.compose.ui.node.O o, J j, int i) {
        return h(new C0896q(o, o.getLayoutDirection()), new C0890k(j, 2, 1, 1), L5.b(0, i, 7)).getWidth();
    }

    default int c(androidx.compose.ui.node.O o, J j, int i) {
        return h(new C0896q(o, o.getLayoutDirection()), new C0890k(j, 1, 1, 1), L5.b(0, i, 7)).getWidth();
    }

    default int f(androidx.compose.ui.node.O o, J j, int i) {
        return h(new C0896q(o, o.getLayoutDirection()), new C0890k(j, 1, 2, 1), L5.b(i, 0, 13)).b();
    }

    L h(M m, J j, long j2);

    default int i(androidx.compose.ui.node.O o, J j, int i) {
        return h(new C0896q(o, o.getLayoutDirection()), new C0890k(j, 2, 2, 1), L5.b(i, 0, 13)).b();
    }
}
