package kotlinx.coroutines.rx3;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.r;
import kotlinx.coroutines.C5028l;
import retrofit2.InterfaceC5179d;
import retrofit2.InterfaceC5182g;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class d implements io.reactivex.rxjava3.core.h, InterfaceC5182g {
    public final /* synthetic */ C5028l a;

    public /* synthetic */ d(C5028l c5028l) {
        this.a = c5028l;
    }

    @Override // io.reactivex.rxjava3.core.h
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        this.a.u(new com.quizlet.ui.compose.modifiers.b(bVar, 13));
    }

    @Override // retrofit2.InterfaceC5182g
    public void f(InterfaceC5179d call, Throwable t) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(t, "t");
        p pVar = r.b;
        this.a.resumeWith(Z.b(t));
    }

    @Override // retrofit2.InterfaceC5182g
    public void k(InterfaceC5179d call, K response) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(response, "response");
        p pVar = r.b;
        this.a.resumeWith(response);
    }

    @Override // io.reactivex.rxjava3.core.h
    public void onComplete() {
        p pVar = r.b;
        this.a.resumeWith(null);
    }

    @Override // io.reactivex.rxjava3.core.h
    public void onError(Throwable th) {
        p pVar = r.b;
        this.a.resumeWith(Z.b(th));
    }

    @Override // io.reactivex.rxjava3.core.h, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        p pVar = r.b;
        this.a.resumeWith(obj);
    }
}
