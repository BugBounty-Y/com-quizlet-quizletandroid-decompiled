package androidx.fragment.app;

/* renamed from: androidx.fragment.app.a0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1122a0 implements InterfaceC1144l0 {
    public final /* synthetic */ Fragment a;

    public C1122a0(Fragment fragment) {
        this.a = fragment;
    }

    @Override // androidx.fragment.app.InterfaceC1144l0
    public final void a(AbstractC1136h0 abstractC1136h0, Fragment fragment) {
        this.a.onAttachFragment(fragment);
    }
}
