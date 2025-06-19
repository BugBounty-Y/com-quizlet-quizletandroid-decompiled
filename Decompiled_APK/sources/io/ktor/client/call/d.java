package io.ktor.client.call;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3216n7;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends b {
    public final byte[] f;
    public final boolean g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(io.ktor.client.c client, io.ktor.client.request.b request, io.ktor.client.statement.b response, byte[] responseBody) {
        super(client);
        Intrinsics.checkNotNullParameter(client, "client");
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(response, "response");
        Intrinsics.checkNotNullParameter(responseBody, "responseBody");
        this.f = responseBody;
        e eVar = new e(this, request);
        Intrinsics.checkNotNullParameter(eVar, "<set-?>");
        this.b = eVar;
        f fVar = new f(this, responseBody, response);
        Intrinsics.checkNotNullParameter(fVar, "<set-?>");
        this.c = fVar;
        this.g = true;
    }

    @Override // io.ktor.client.call.b
    public final boolean b() {
        return this.g;
    }

    @Override // io.ktor.client.call.b
    public final Object e() {
        return AbstractC3216n7.a(this.f);
    }
}
