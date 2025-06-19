package kotlinx.coroutines.rx3;

import kotlinx.coroutines.AbstractC4972a;

/* loaded from: classes3.dex */
public final class e implements io.reactivex.rxjava3.functions.c {
    public final AbstractC4972a a;

    public e(AbstractC4972a abstractC4972a) {
        this.a = abstractC4972a;
    }

    @Override // io.reactivex.rxjava3.functions.c
    public final void cancel() {
        this.a.j(null);
    }
}
