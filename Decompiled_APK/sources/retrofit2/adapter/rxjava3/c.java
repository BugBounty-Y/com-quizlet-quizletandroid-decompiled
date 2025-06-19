package retrofit2.adapter.rxjava3;

import retrofit2.InterfaceC5179d;

/* loaded from: classes3.dex */
public final class c implements io.reactivex.rxjava3.disposables.b {
    public final InterfaceC5179d a;
    public volatile boolean b;

    public c(InterfaceC5179d interfaceC5179d) {
        this.a = interfaceC5179d;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.b = true;
        this.a.cancel();
    }
}
