package retrofit2.adapter.rxjava3;

import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.l;

/* loaded from: classes3.dex */
public final class b extends i {
    public final /* synthetic */ int a;
    public final com.jakewharton.rxbinding4.a b;

    public /* synthetic */ b(com.jakewharton.rxbinding4.a aVar, int i) {
        this.a = i;
        this.b = aVar;
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(l lVar) {
        switch (this.a) {
            case 0:
                this.b.c(new a(lVar));
                break;
            default:
                this.b.c(new com.quizlet.infra.legacysyncengine.utils.b(lVar, 1));
                break;
        }
    }
}
