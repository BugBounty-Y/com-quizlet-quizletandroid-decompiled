package androidx.credentials;

import androidx.credentials.exceptions.GetCredentialException;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;
import retrofit2.HttpException;
import retrofit2.InterfaceC5179d;
import retrofit2.InterfaceC5182g;
import retrofit2.K;

/* loaded from: classes.dex */
public final class d implements e, io.reactivex.rxjava3.core.q, InterfaceC5182g {
    public final /* synthetic */ C5028l a;

    public /* synthetic */ d(C5028l c5028l) {
        this.a = c5028l;
    }

    @Override // io.reactivex.rxjava3.core.q
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        this.a.u(new com.quizlet.ui.compose.modifiers.b(bVar, 13));
    }

    @Override // androidx.credentials.e
    public void b(Object obj) {
        GetCredentialException e = (GetCredentialException) obj;
        Intrinsics.checkNotNullParameter(e, "e");
        C5028l c5028l = this.a;
        if (c5028l.w()) {
            kotlin.p pVar = kotlin.r.b;
            c5028l.resumeWith(Z.b(e));
        }
    }

    @Override // retrofit2.InterfaceC5182g
    public void f(InterfaceC5179d call, Throwable t) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(t, "t");
        kotlin.p pVar = kotlin.r.b;
        this.a.resumeWith(Z.b(t));
    }

    @Override // retrofit2.InterfaceC5182g
    public void k(InterfaceC5179d call, K response) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(response, "response");
        boolean zD = response.a.d();
        C5028l c5028l = this.a;
        if (zD) {
            kotlin.p pVar = kotlin.r.b;
            c5028l.resumeWith(response.b);
        } else {
            kotlin.p pVar2 = kotlin.r.b;
            c5028l.resumeWith(Z.b(new HttpException(response)));
        }
    }

    @Override // io.reactivex.rxjava3.core.q
    public void onError(Throwable th) {
        kotlin.p pVar = kotlin.r.b;
        this.a.resumeWith(Z.b(th));
    }

    @Override // androidx.credentials.e
    public void onResult(Object obj) {
        p result = (p) obj;
        Intrinsics.checkNotNullParameter(result, "result");
        C5028l c5028l = this.a;
        if (c5028l.w()) {
            kotlin.p pVar = kotlin.r.b;
            c5028l.resumeWith(result);
        }
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        kotlin.p pVar = kotlin.r.b;
        this.a.resumeWith(obj);
    }
}
