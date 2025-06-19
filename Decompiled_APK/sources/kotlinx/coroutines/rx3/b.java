package kotlinx.coroutines.rx3;

import androidx.compose.ui.input.pointer.u;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.db.billing.model.DBSubscription;
import io.reactivex.rxjava3.core.l;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.r;
import kotlinx.coroutines.C5028l;

/* loaded from: classes3.dex */
public final class b implements l {
    public io.reactivex.rxjava3.disposables.b a;
    public boolean b;
    public final /* synthetic */ C5028l c;

    public b(C5028l c5028l) {
        a aVar = a.b;
        this.c = c5028l;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        this.a = bVar;
        this.c.u(new u(bVar, 6));
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        a aVar = a.b;
        C5028l c5028l = this.c;
        if (this.b) {
            return;
        }
        this.b = true;
        p pVar = r.b;
        c5028l.resumeWith(obj);
        io.reactivex.rxjava3.disposables.b bVar = this.a;
        if (bVar != null) {
            bVar.dispose();
        } else {
            Intrinsics.m(DBSubscription.TABLE_NAME);
            throw null;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        boolean z = this.b;
        C5028l c5028l = this.c;
        if (z) {
            if (c5028l.w()) {
                p pVar = r.b;
                c5028l.resumeWith(null);
                return;
            }
            return;
        }
        a aVar = a.b;
        a aVar2 = a.b;
        if (c5028l.w()) {
            p pVar2 = r.b;
            c5028l.resumeWith(Z.b(new NoSuchElementException("No value received via onNext for " + aVar2)));
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        p pVar = r.b;
        this.c.resumeWith(Z.b(th));
    }
}
