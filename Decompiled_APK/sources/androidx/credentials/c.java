package androidx.credentials;

import androidx.credentials.exceptions.ClearCredentialException;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import kotlin.KotlinNullPointerException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;
import okhttp3.C;
import retrofit2.C5191p;
import retrofit2.HttpException;
import retrofit2.InterfaceC5179d;
import retrofit2.InterfaceC5182g;
import retrofit2.K;

/* loaded from: classes.dex */
public final class c implements e, io.reactivex.rxjava3.core.b, InterfaceC5182g {
    public final /* synthetic */ C5028l a;

    public /* synthetic */ c(C5028l c5028l) {
        this.a = c5028l;
    }

    @Override // io.reactivex.rxjava3.core.b
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        this.a.u(new com.quizlet.ui.compose.modifiers.b(bVar, 13));
    }

    @Override // androidx.credentials.e
    public void b(Object obj) {
        ClearCredentialException e = (ClearCredentialException) obj;
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
        if (!zD) {
            kotlin.p pVar = kotlin.r.b;
            c5028l.resumeWith(Z.b(new HttpException(response)));
            return;
        }
        Object obj = response.b;
        if (obj != null) {
            kotlin.p pVar2 = kotlin.r.b;
            c5028l.resumeWith(obj);
            return;
        }
        C cQ = call.Q();
        cQ.getClass();
        Intrinsics.checkNotNullParameter(C5191p.class, DBUserFields.Names.USER_UPGRADE_TYPE);
        Object objCast = C5191p.class.cast(cQ.e.get(C5191p.class));
        Intrinsics.d(objCast);
        C5191p c5191p = (C5191p) objCast;
        KotlinNullPointerException kotlinNullPointerException = new KotlinNullPointerException("Response from " + c5191p.a.getName() + '.' + c5191p.c.getName() + " was null but response body type was declared as non-null");
        kotlin.p pVar3 = kotlin.r.b;
        c5028l.resumeWith(Z.b(kotlinNullPointerException));
    }

    @Override // io.reactivex.rxjava3.core.b
    public void onComplete() {
        kotlin.p pVar = kotlin.r.b;
        this.a.resumeWith(Unit.a);
    }

    @Override // io.reactivex.rxjava3.core.b
    public void onError(Throwable th) {
        kotlin.p pVar = kotlin.r.b;
        this.a.resumeWith(Z.b(th));
    }

    @Override // androidx.credentials.e
    public void onResult(Object obj) {
        C5028l c5028l = this.a;
        if (c5028l.w()) {
            kotlin.p pVar = kotlin.r.b;
            c5028l.resumeWith(Unit.a);
        }
    }
}
