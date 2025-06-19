package io.reactivex.rxjava3.internal.disposables;

import io.reactivex.rxjava3.core.l;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class b implements io.reactivex.rxjava3.operators.a {
    public static final b a;
    public static final b b;
    public static final /* synthetic */ b[] c;

    static {
        b bVar = new b("INSTANCE", 0);
        a = bVar;
        b bVar2 = new b("NEVER", 1);
        b = bVar2;
        c = new b[]{bVar, bVar2};
    }

    public static void a(l lVar) {
        lVar.a(a);
        lVar.onComplete();
    }

    public static void b(Throwable th, io.reactivex.rxjava3.core.b bVar) {
        bVar.a(a);
        bVar.onError(th);
    }

    public static void d(Throwable th, l lVar) {
        lVar.a(a);
        lVar.onError(th);
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) c.clone();
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final void clear() {
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
    }

    @Override // io.reactivex.rxjava3.operators.b
    public final int h(int i) {
        return 2;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean isEmpty() {
        return true;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean offer(Object obj) {
        throw new UnsupportedOperationException("Should not be called!");
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final Object poll() {
        return null;
    }
}
