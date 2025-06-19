package io.reactivex.rxjava3.internal.operators.maybe;

/* loaded from: classes3.dex */
public final class s extends a {
    public final /* synthetic */ int b;
    public final Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ s(io.reactivex.rxjava3.core.g gVar, Object obj, int i) {
        super(gVar);
        this.b = i;
        this.c = obj;
    }

    @Override // io.reactivex.rxjava3.core.g
    public final void f(io.reactivex.rxjava3.core.h hVar) {
        switch (this.b) {
            case 0:
                this.a.e(new g(hVar, (io.reactivex.rxjava3.functions.i) this.c, 1));
                break;
            default:
                this.a.e(new io.reactivex.rxjava3.internal.observers.e(4, hVar, (com.quizlet.remote.model.progress.e) this.c));
                break;
        }
    }
}
