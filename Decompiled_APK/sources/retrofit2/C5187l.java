package retrofit2;

import java.util.concurrent.Executor;

/* renamed from: retrofit2.l, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5187l implements InterfaceC5179d {
    public final Executor a;
    public final InterfaceC5179d b;

    public C5187l(Executor executor, InterfaceC5179d interfaceC5179d) {
        this.a = executor;
        this.b = interfaceC5179d;
    }

    @Override // retrofit2.InterfaceC5179d
    public final boolean C() {
        return this.b.C();
    }

    @Override // retrofit2.InterfaceC5179d
    public final okhttp3.C Q() {
        return this.b.Q();
    }

    @Override // retrofit2.InterfaceC5179d
    public final K a() {
        return this.b.a();
    }

    @Override // retrofit2.InterfaceC5179d
    public final void cancel() {
        this.b.cancel();
    }

    @Override // retrofit2.InterfaceC5179d
    public final void j(InterfaceC5182g interfaceC5182g) {
        this.b.j(new com.quizlet.remote.model.report.c(this, interfaceC5182g));
    }

    @Override // retrofit2.InterfaceC5179d
    public final InterfaceC5179d clone() {
        return new C5187l(this.a, this.b.clone());
    }
}
