package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.widget.ImageView;
import com.bumptech.glide.Glide;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.pubmatic.sdk.video.c;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.j4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3649j4 {
    public static final /* synthetic */ int a = 0;

    public static final void a(int i, ImageView imageView, String str, String str2, String navigatedFrom) {
        Intrinsics.checkNotNullParameter(imageView, "<this>");
        Intrinsics.checkNotNullParameter(navigatedFrom, "navigatedFrom");
        com.onetrust.otpublishers.headless.UI.extensions.b bVar = new com.onetrust.otpublishers.headless.UI.extensions.b(i, imageView, navigatedFrom, str, str2);
        Integer numValueOf = Integer.valueOf(c.a.DEFAULT_MEDIA_URI_TIMEOUT);
        if (str != null && str.length() != 0) {
            com.bumptech.glide.m mVarD = Glide.d(imageView);
            mVarD.getClass();
            com.bumptech.glide.k kVarD = new com.bumptech.glide.k(mVarD.a, mVarD, Drawable.class, mVarD.b).D(str);
            kVarD.getClass();
            ((com.bumptech.glide.k) kVarD.m(com.bumptech.glide.load.resource.bitmap.m.b, new com.bumptech.glide.load.resource.bitmap.t(), true)).b(new com.bumptech.glide.request.f().o(com.bumptech.glide.load.model.stream.a.b, numValueOf)).B(bVar).z(imageView);
            return;
        }
        com.onetrust.otpublishers.headless.UI.extensions.a aVar = new com.onetrust.otpublishers.headless.UI.extensions.a(0, navigatedFrom, str2);
        try {
            com.bumptech.glide.m mVarD2 = Glide.d(imageView);
            mVarD2.getClass();
            com.bumptech.glide.k kVarD2 = new com.bumptech.glide.k(mVarD2.a, mVarD2, Drawable.class, mVarD2.b).D(str2);
            kVarD2.getClass();
            ((com.bumptech.glide.k) kVarD2.m(com.bumptech.glide.load.resource.bitmap.m.b, new com.bumptech.glide.load.resource.bitmap.t(), true)).b(new com.bumptech.glide.request.f().o(com.bumptech.glide.load.model.stream.a.b, numValueOf)).B(aVar).z(imageView);
        } catch (Exception e) {
            OTLogger.c("OneTrust", 3, "error on showing " + navigatedFrom + " logo, " + e);
        }
    }

    public static final void b(ImageView imageView, String str) {
        Intrinsics.checkNotNullParameter(imageView, "<this>");
        if (str == null || str.length() == 0) {
            return;
        }
        imageView.getDrawable().setTint(Color.parseColor(str));
    }
}
