package com.google.android.gms.ads.internal.util.client;

import android.util.JsonWriter;
import com.android.billingclient.api.Purchase;
import java.io.IOException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class d implements e, io.reactivex.rxjava3.functions.h {
    public String a;

    public /* synthetic */ d(String str) {
        this.a = str;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        com.quizlet.billing.model.a it2 = (com.quizlet.billing.model.a) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.getClass();
        String sku = this.a;
        Intrinsics.checkNotNullParameter(sku, "sku");
        return com.google.android.gms.common.wrappers.a.d((Purchase) it2.c.get(sku));
    }

    @Override // com.google.android.gms.ads.internal.util.client.e
    public void i(JsonWriter jsonWriter) throws IOException {
        Object obj = f.b;
        jsonWriter.name("params").beginObject();
        String str = this.a;
        if (str != null) {
            jsonWriter.name("error_description").value(str);
        }
        jsonWriter.endObject();
    }
}
