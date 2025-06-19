package androidx.navigation.compose;

/* loaded from: classes.dex */
public final class t extends androidx.navigation.C {
    public final s g;
    public final androidx.compose.ui.window.r h;
    public final androidx.compose.runtime.internal.d i;

    public t(s sVar, String str, androidx.compose.ui.window.r rVar, androidx.compose.runtime.internal.d dVar) {
        super(sVar, str);
        this.g = sVar;
        this.h = rVar;
        this.i = dVar;
    }

    @Override // androidx.navigation.C
    public final androidx.navigation.B b() {
        return new r(this.g, this.h, this.i);
    }
}
