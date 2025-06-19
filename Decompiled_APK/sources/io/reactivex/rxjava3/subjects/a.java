package io.reactivex.rxjava3.subjects;

/* loaded from: classes3.dex */
public final class a extends io.reactivex.rxjava3.internal.observers.f {
    public final b c;

    public a(io.reactivex.rxjava3.core.l lVar, b bVar) {
        super(lVar);
        this.c = bVar;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (getAndSet(4) != 4) {
            this.c.z(this);
        }
    }
}
