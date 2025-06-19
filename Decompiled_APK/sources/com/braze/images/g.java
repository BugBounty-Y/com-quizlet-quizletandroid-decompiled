package com.braze.images;

import android.content.Context;
import android.graphics.Bitmap;
import android.net.TrafficStats;
import android.widget.ImageView;
import androidx.glance.appwidget.protobuf.Z;
import com.braze.AbstractC1484j;
import com.braze.R$string;
import com.braze.W;
import com.braze.enums.BrazeViewBounds;
import com.braze.support.BrazeLogger;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;
import kotlinx.coroutines.internal.m;

/* loaded from: classes.dex */
public final class g extends i implements Function2 {
    public Bitmap a;
    public int b;
    public final /* synthetic */ DefaultBrazeImageLoader c;
    public final /* synthetic */ Context d;
    public final /* synthetic */ String e;
    public final /* synthetic */ BrazeViewBounds f;
    public final /* synthetic */ ImageView g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(DefaultBrazeImageLoader defaultBrazeImageLoader, Context context, String str, BrazeViewBounds brazeViewBounds, ImageView imageView, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.c = defaultBrazeImageLoader;
        this.d = context;
        this.e = str;
        this.f = brazeViewBounds;
        this.g = imageView;
    }

    public static final String a(String str) {
        return AbstractC1484j.a("Failed to retrieve bitmap from url: ", str);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.c, this.d, this.e, this.f, this.g, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Bitmap bitmap;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.b;
        if (i == 0) {
            Z.e(obj);
            TrafficStats.setThreadStatsTag(1337);
            Bitmap bitmapFromUrl = this.c.getBitmapFromUrl(this.d, this.e, this.f);
            if (bitmapFromUrl == null) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, DefaultBrazeImageLoader.TAG, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new W(this.e, 26), 14, (Object) null);
            } else {
                String str = this.e;
                Object tag = this.g.getTag(R$string.com_braze_image_lru_cache_image_url_key);
                Intrinsics.e(tag, "null cannot be cast to non-null type kotlin.String");
                if (Intrinsics.b(str, (String) tag)) {
                    kotlinx.coroutines.scheduling.e eVar = O.a;
                    kotlinx.coroutines.android.d dVar = m.a;
                    e eVar2 = new e(this.g, bitmapFromUrl, null);
                    this.a = bitmapFromUrl;
                    this.b = 1;
                    if (E.J(dVar, eVar2, this) == aVar) {
                        return aVar;
                    }
                    bitmap = bitmapFromUrl;
                }
            }
            return Unit.a;
        }
        if (i != 1) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        bitmap = this.a;
        Z.e(obj);
        BrazeViewBounds brazeViewBounds = this.f;
        ImageView imageView = this.g;
        imageView.addOnLayoutChangeListener(new f(brazeViewBounds, imageView, bitmap));
        return Unit.a;
    }
}
