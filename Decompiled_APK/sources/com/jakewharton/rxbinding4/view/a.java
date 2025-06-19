package com.jakewharton.rxbinding4.view;

import android.view.View;
import io.reactivex.rxjava3.core.l;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a extends io.reactivex.rxjava3.android.a implements View.OnClickListener {
    public final View b;
    public final l c;

    public a(View view, l observer) {
        Intrinsics.f(view, "view");
        Intrinsics.f(observer, "observer");
        this.b = view;
        this.c = observer;
    }

    @Override // io.reactivex.rxjava3.android.a
    public final void a() {
        this.b.setOnClickListener(null);
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View v) {
        Intrinsics.f(v, "v");
        if (this.a.get()) {
            return;
        }
        this.c.b(Unit.a);
    }
}
