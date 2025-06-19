package com.google.android.gms.ads.internal.client;

import android.os.RemoteException;
import com.quizlet.remote.model.base.ApiError;
import com.quizlet.remote.service.NetworkException;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.ads.internal.client.h0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1597h0 implements io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a = 0;
    public final String b;

    public C1597h0(String str) {
        this.b = str;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        NetworkException networkException;
        ApiError apiError;
        Integer num;
        Throwable error = (Throwable) obj;
        Intrinsics.checkNotNullParameter(error, "error");
        Intrinsics.checkNotNullParameter(error, "error");
        return ((error instanceof NetworkException) && (apiError = (networkException = (NetworkException) error).a) != null && (num = apiError.c) != null && num.intValue() == 404 && Intrinsics.b(networkException.a.b, "exception_not_found")) ? io.reactivex.rxjava3.core.p.d(new NoSuchElementException(this.b)) : io.reactivex.rxjava3.core.p.d(error);
    }

    public String toString() {
        switch (this.a) {
            case 0:
                return this.b;
            default:
                return super.toString();
        }
    }

    public C1597h0(InterfaceC1595g0 interfaceC1595g0) {
        String strZze;
        try {
            strZze = interfaceC1595g0.zze();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
            strZze = null;
        }
        this.b = strZze;
    }
}
