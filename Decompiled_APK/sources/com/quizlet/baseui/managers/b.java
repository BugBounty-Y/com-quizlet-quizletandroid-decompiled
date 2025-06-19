package com.quizlet.baseui.managers;

import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import com.quizlet.quizletandroid.t;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes2.dex */
public final class b implements InterfaceC1250k {
    public final t a;
    public final u b;
    public final u c;
    public final u d;

    public b(t compositeDisposableProvider) {
        Intrinsics.checkNotNullParameter(compositeDisposableProvider, "compositeDisposableProvider");
        this.a = compositeDisposableProvider;
        final int i = 0;
        this.b = l.b(new Function0(this) { // from class: com.quizlet.baseui.managers.a
            public final /* synthetic */ b b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i) {
                }
                return (io.reactivex.rxjava3.disposables.a) this.b.a.get();
            }
        });
        final int i2 = 1;
        this.c = l.b(new Function0(this) { // from class: com.quizlet.baseui.managers.a
            public final /* synthetic */ b b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i2) {
                }
                return (io.reactivex.rxjava3.disposables.a) this.b.a.get();
            }
        });
        final int i3 = 2;
        this.d = l.b(new Function0(this) { // from class: com.quizlet.baseui.managers.a
            public final /* synthetic */ b b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i3) {
                }
                return (io.reactivex.rxjava3.disposables.a) this.b.a.get();
            }
        });
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onDestroy(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(owner, "owner");
        Object value = this.d.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((io.reactivex.rxjava3.disposables.a) value).d();
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onPause(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(owner, "owner");
        Object value = this.b.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((io.reactivex.rxjava3.disposables.a) value).d();
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onStop(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(owner, "owner");
        Object value = this.c.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((io.reactivex.rxjava3.disposables.a) value).d();
    }
}
