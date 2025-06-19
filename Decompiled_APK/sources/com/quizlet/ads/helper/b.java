package com.quizlet.ads.helper;

import android.content.Context;
import android.os.RemoteException;
import com.braze.ui.h;
import com.google.android.gms.ads.admanager.AdManagerAdRequest;
import com.google.android.gms.ads.e;
import com.google.android.gms.ads.formats.AdManagerAdViewOptions;
import com.google.android.gms.ads.internal.util.client.i;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3170i6;
import com.quizlet.ads.c;
import com.quizlet.shared.usecase.folderstudymaterials.d;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public final class b {
    public final Context a;

    public b(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    public static AdManagerAdRequest a(Map customTargets, Map basicTargets) {
        Intrinsics.checkNotNullParameter(customTargets, "customTargets");
        Intrinsics.checkNotNullParameter(basicTargets, "basicTargets");
        AdManagerAdRequest.Builder builder = new AdManagerAdRequest.Builder();
        for (Map.Entry entry : customTargets.entrySet()) {
            builder.addCustomTargeting((String) entry.getKey(), (List<String>) entry.getValue());
        }
        for (Map.Entry entry2 : basicTargets.entrySet()) {
            builder.addCustomTargeting((String) entry2.getKey(), (String) entry2.getValue());
        }
        AdManagerAdRequest adManagerAdRequestBuild = builder.build();
        Intrinsics.checkNotNullExpressionValue(adManagerAdRequestBuild, "build(...)");
        return adManagerAdRequestBuild;
    }

    public final e b(c adUnit, Function1 onAdFailedToLoad, Function1 onAdManagerLoaded) {
        Intrinsics.checkNotNullParameter(adUnit, "adUnit");
        Intrinsics.checkNotNullParameter(onAdFailedToLoad, "onAdFailedToLoad");
        Intrinsics.checkNotNullParameter(onAdManagerLoaded, "onAdManagerLoaded");
        Context context = this.a;
        e eVar = new e(context, context.getResources().getString(adUnit.a));
        eVar.c(new a(onAdFailedToLoad));
        h hVar = new h(onAdManagerLoaded);
        com.google.android.gms.ads.h[] hVarArr = (com.google.android.gms.ads.h[]) adUnit.a(AbstractC3170i6.i(context)).toArray(new com.google.android.gms.ads.h[0]);
        eVar.b(hVar, (com.google.android.gms.ads.h[]) Arrays.copyOf(hVarArr, hVarArr.length));
        try {
            eVar.b.S3(new AdManagerAdViewOptions(new d(8)));
        } catch (RemoteException e) {
            i.i("Failed to specify Ad Manager banner ad options", e);
        }
        Intrinsics.checkNotNullExpressionValue(eVar, "with(...)");
        return eVar;
    }
}
