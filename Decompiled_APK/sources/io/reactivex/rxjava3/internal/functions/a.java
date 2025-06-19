package io.reactivex.rxjava3.internal.functions;

import io.reactivex.rxjava3.functions.j;
import java.util.ArrayList;

/* loaded from: classes3.dex */
public final class a implements j {
    public final int a;

    public a(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.j
    public final Object get() {
        return new ArrayList(this.a);
    }
}
