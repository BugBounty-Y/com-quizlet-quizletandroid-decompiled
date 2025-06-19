package com.airbnb.lottie.compose;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.util.Base64;
import androidx.glance.appwidget.protobuf.Z;
import com.airbnb.lottie.w;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlin.text.StringsKt;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class r extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ com.airbnb.lottie.h j;
    public final /* synthetic */ Context k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(com.airbnb.lottie.h hVar, Context context, String str, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.j = hVar;
        this.k = context;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new r(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((r) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws IOException {
        String str;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        for (w wVar : ((HashMap) this.j.c()).values()) {
            Intrinsics.d(wVar);
            Bitmap bitmap = wVar.f;
            String str2 = wVar.d;
            if (bitmap == null && D.r(str2, "data:", false) && StringsKt.M(str2, "base64,", 0, false, 6) > 0) {
                try {
                    String strSubstring = str2.substring(StringsKt.L(str2, ',', 0, false, 6) + 1);
                    Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                    byte[] bArrDecode = Base64.decode(strSubstring, 0);
                    BitmapFactory.Options options = new BitmapFactory.Options();
                    options.inScaled = true;
                    options.inDensity = 160;
                    wVar.f = BitmapFactory.decodeByteArray(bArrDecode, 0, bArrDecode.length, options);
                } catch (IllegalArgumentException e) {
                    com.airbnb.lottie.utils.c.c("data URL did not have correct base64 format.", e);
                }
            }
            Context context = this.k;
            if (wVar.f == null && (str = this.l) != null) {
                try {
                    InputStream inputStreamOpen = context.getAssets().open(str + str2);
                    Intrinsics.d(inputStreamOpen);
                    Bitmap bitmapDecodeStream = null;
                    try {
                        BitmapFactory.Options options2 = new BitmapFactory.Options();
                        options2.inScaled = true;
                        options2.inDensity = 160;
                        bitmapDecodeStream = BitmapFactory.decodeStream(inputStreamOpen, null, options2);
                    } catch (IllegalArgumentException e2) {
                        com.airbnb.lottie.utils.c.c("Unable to decode image.", e2);
                    }
                    if (bitmapDecodeStream != null) {
                        wVar.f = com.airbnb.lottie.utils.i.d(bitmapDecodeStream, wVar.a, wVar.b);
                    }
                } catch (IOException e3) {
                    com.airbnb.lottie.utils.c.c("Unable to open asset.", e3);
                }
            }
        }
        return Unit.a;
    }
}
