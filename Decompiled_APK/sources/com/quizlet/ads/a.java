package com.quizlet.ads;

import com.amazon.device.ads.AdError;
import com.amazon.device.ads.DTBAdCallback;
import com.amazon.device.ads.DTBAdResponse;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.io.IOException;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.C;
import okhttp3.H;
import okhttp3.InterfaceC5076e;
import okhttp3.InterfaceC5077f;

/* loaded from: classes2.dex */
public final class a implements DTBAdCallback, InterfaceC5077f {
    public final /* synthetic */ io.reactivex.rxjava3.internal.operators.single.c a;

    public /* synthetic */ a(io.reactivex.rxjava3.internal.operators.single.c cVar) {
        this.a = cVar;
    }

    @Override // okhttp3.InterfaceC5077f
    public void onFailure(InterfaceC5076e call, IOException t) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(t, "e");
        okhttp3.internal.connection.g gVar = (okhttp3.internal.connection.g) call;
        if (!gVar.o) {
            timber.log.c.a.p(t);
            io.reactivex.rxjava3.internal.operators.single.c cVar = this.a;
            Intrinsics.checkNotNullParameter(cVar, "<this>");
            Intrinsics.checkNotNullParameter(t, "t");
            if (io.reactivex.rxjava3.internal.disposables.a.b((io.reactivex.rxjava3.disposables.b) cVar.get()) || cVar.b(t)) {
                return;
            }
            C7.c(t);
            return;
        }
        timber.log.a aVar = timber.log.c.a;
        C c = gVar.b;
        aVar.i(t, "Error for canceled call: " + c.b + " " + c.a, new Object[0]);
    }

    @Override // okhttp3.InterfaceC5077f
    public void onResponse(InterfaceC5076e call, H response) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(response, "response");
        this.a.onSuccess(response);
    }

    @Override // com.amazon.device.ads.DTBAdCallback
    public void onSuccess(DTBAdResponse dtbAdResponse) {
        Intrinsics.checkNotNullParameter(dtbAdResponse, "dtbAdResponse");
        this.a.onSuccess(dtbAdResponse.getDefaultDisplayAdsRequestCustomParams());
    }

    @Override // com.amazon.device.ads.DTBAdCallback
    public void onFailure(AdError adError) {
        Intrinsics.checkNotNullParameter(adError, "adError");
        this.a.onSuccess(V.c());
    }
}
