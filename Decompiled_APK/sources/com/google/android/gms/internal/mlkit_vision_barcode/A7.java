package com.google.android.gms.internal.mlkit_vision_barcode;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class A7 {
    public static final /* synthetic */ int a = 0;

    public static final void a(io.reactivex.rxjava3.disposables.b addTo, io.reactivex.rxjava3.disposables.a compositeDisposable) {
        Intrinsics.checkNotNullParameter(addTo, "$this$addTo");
        Intrinsics.checkNotNullParameter(compositeDisposable, "compositeDisposable");
        compositeDisposable.b(addTo);
    }

    public abstract void b(int i, byte[] bArr, int i2);
}
