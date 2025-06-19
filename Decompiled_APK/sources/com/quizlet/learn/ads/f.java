package com.quizlet.learn.ads;

import android.content.Context;
import android.os.RemoteException;
import androidx.compose.ui.platform.C0960p;
import com.google.android.gms.ads.admanager.AdManagerAdRequest;
import com.google.android.gms.ads.admanager.AdManagerAdView;
import com.google.android.gms.ads.formats.AdManagerAdViewOptions;
import com.google.android.gms.ads.internal.client.G;
import com.google.android.gms.ads.internal.util.client.i;
import com.google.android.gms.internal.ads.BinderC1825a9;
import com.google.android.gms.internal.ads.C1732Mb;
import com.google.android.gms.internal.ads.zzbfv;
import com.quizlet.ads.data.AdDataType;
import com.quizlet.quizletandroid.R;
import io.reactivex.rxjava3.core.p;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements com.google.android.gms.ads.formats.c {
    public final Context a;
    public final com.google.mlkit.vision.documentscanner.internal.c b;
    public final com.quizlet.ads.b c;
    public final c d;
    public final com.quizlet.ads.g e;
    public boolean f;
    public int g;
    public d h;
    public com.quizlet.ads.c i;

    public f(Context context, com.google.mlkit.vision.documentscanner.internal.c adBidTargetsProvider, com.quizlet.ads.b adTargetsManager, c learnAdLoaderHelper, com.quizlet.ads.g adsRepository) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(adBidTargetsProvider, "adBidTargetsProvider");
        Intrinsics.checkNotNullParameter(adTargetsManager, "adTargetsManager");
        Intrinsics.checkNotNullParameter(learnAdLoaderHelper, "learnAdLoaderHelper");
        Intrinsics.checkNotNullParameter(adsRepository, "adsRepository");
        this.a = context;
        this.b = adBidTargetsProvider;
        this.c = adTargetsManager;
        this.d = learnAdLoaderHelper;
        this.e = adsRepository;
    }

    @Override // com.google.android.gms.ads.formats.c
    public final void a(AdManagerAdView data) {
        Intrinsics.checkNotNullParameter(data, "adManagerView");
        com.quizlet.ads.g gVar = this.e;
        gVar.getClass();
        Intrinsics.checkNotNullParameter(data, "data");
        gVar.b = data;
        d dVar = this.h;
        if (dVar != null) {
            AdDataType.BannerAdType adDataType = AdDataType.BannerAdType.b;
            Intrinsics.checkNotNullParameter(adDataType, "adDataType");
            ((h) dVar).d = adDataType;
        }
    }

    public final void b() {
        G g;
        com.quizlet.ads.c cVar = this.i;
        if (cVar == null) {
            Intrinsics.m("adUnit");
            throw null;
        }
        List adSizes = cVar.a(this.f);
        String adUnitId = this.a.getResources().getString(this.g);
        Intrinsics.checkNotNullExpressionValue(adUnitId, "getString(...)");
        e adListener = new e();
        boolean z = this.f;
        HashMap formatIds = V.e(new Pair(com.quizlet.ads.data.d.b, Integer.valueOf(R.string.learn_mode_native_ad_format_id)), new Pair(com.quizlet.ads.data.d.c, Integer.valueOf(R.string.learn_mode_native_video_ad_format_id)), new Pair(com.quizlet.ads.data.d.d, Integer.valueOf(R.string.learn_mode_outstream_video_ad_format_id)));
        if (!z) {
            formatIds.put(com.quizlet.ads.data.d.e, Integer.valueOf(R.string.learn_mode_outstream_video_ad_4_5_format_id));
            formatIds.put(com.quizlet.ads.data.d.f, Integer.valueOf(R.string.learn_mode_outstream_video_ad_9_16_format_id));
        }
        C0960p onNativeAddLoaded = new C0960p(2, this, f.class, "onNativeAddLoaded", "onNativeAddLoaded$learn_release(Lcom/google/android/gms/ads/nativead/NativeCustomFormatAd;Lcom/quizlet/ads/data/AdType;)V", 0, 21);
        c cVar2 = this.d;
        Intrinsics.checkNotNullParameter(adUnitId, "adUnitId");
        Intrinsics.checkNotNullParameter(adSizes, "adSizes");
        Intrinsics.checkNotNullParameter(adListener, "adListener");
        Intrinsics.checkNotNullParameter(this, "adManagerLister");
        Intrinsics.checkNotNullParameter(formatIds, "formatIds");
        Intrinsics.checkNotNullParameter(onNativeAddLoaded, "onNativeAddLoaded");
        Context context = cVar2.a;
        com.google.android.gms.ads.e eVar = new com.google.android.gms.ads.e(context, adUnitId);
        eVar.c(adListener);
        com.google.android.gms.ads.h[] hVarArr = (com.google.android.gms.ads.h[]) adSizes.toArray(new com.google.android.gms.ads.h[0]);
        eVar.b(this, (com.google.android.gms.ads.h[]) Arrays.copyOf(hVarArr, hVarArr.length));
        Iterator it2 = formatIds.entrySet().iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            g = eVar.b;
            if (!zHasNext) {
                break;
            }
            Map.Entry entry = (Map.Entry) it2.next();
            com.quizlet.ads.data.d dVar = (com.quizlet.ads.data.d) entry.getKey();
            String string = context.getString(((Number) entry.getValue()).intValue());
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
            try {
                g.i3(string, new BinderC1825a9(new C1732Mb(new com.google.firebase.tracing.a(20, onNativeAddLoaded, dVar)), 1), null);
            } catch (RemoteException e) {
                i.i("Failed to add custom format ad listener", e);
            }
        }
        try {
            g.S3(new AdManagerAdViewOptions(new com.quizlet.shared.usecase.folderstudymaterials.d(8)));
        } catch (RemoteException e2) {
            i.i("Failed to specify Ad Manager banner ad options", e2);
        }
        try {
            g.J1(new zzbfv(4, false, -1, false, 1, null, false, 0, 0, false, 1 - 1));
        } catch (RemoteException e3) {
            i.i("Failed to specify native ad options", e3);
        }
        com.google.android.gms.ads.f fVarA = eVar.a();
        Intrinsics.checkNotNullExpressionValue(fVarA, "build(...)");
        com.quizlet.ads.c cVar3 = this.i;
        if (cVar3 == null) {
            Intrinsics.m("adUnit");
            throw null;
        }
        io.reactivex.rxjava3.internal.operators.flowable.b bidsParam = this.b.g(cVar3);
        p basicTargets = this.c.a();
        Intrinsics.checkNotNullParameter(bidsParam, "bidsParam");
        Intrinsics.checkNotNullParameter(basicTargets, "basicTargets");
        AdManagerAdRequest.Builder builder = new AdManagerAdRequest.Builder();
        io.reactivex.rxjava3.internal.observers.e eVarI = p.p(bidsParam, basicTargets, a.a).i(new b(builder), io.reactivex.rxjava3.internal.functions.d.e);
        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
        ((io.reactivex.rxjava3.disposables.a) cVar2.c.getValue()).b(eVarI);
        AdManagerAdRequest adManagerAdRequestBuild = builder.build();
        Intrinsics.checkNotNullExpressionValue(adManagerAdRequestBuild, "build(...)");
        fVarA.b(adManagerAdRequestBuild);
    }
}
