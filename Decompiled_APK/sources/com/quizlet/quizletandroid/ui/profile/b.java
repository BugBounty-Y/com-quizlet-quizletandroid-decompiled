package com.quizlet.quizletandroid.ui.profile;

import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.VectorDrawable;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.C4161r0;
import com.quizlet.data.model.C4185z0;
import com.quizlet.data.model.S;
import com.quizlet.remote.model.entitlements.RemoteEntitlementData;
import com.quizlet.remote.model.entitlements.RemoteMeteringMeta;
import com.quizlet.remote.model.login.EmailCheckResponse;
import com.quizlet.remote.model.set.RemoteIrrelevantRecommendation;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.EnumC5145a;

/* loaded from: classes3.dex */
public final class b implements com.quizlet.mapper.a, io.reactivex.rxjava3.functions.h, com.quizlet.remote.mapper.base.b {
    public static final void b(Context context, int i, int i2) {
        Bitmap bitmap;
        int height;
        EnumC5145a enumC5145a = AztecText.q1;
        Drawable drawableF = com.facebook.appevents.g.f(context, i);
        if (drawableF instanceof BitmapDrawable) {
            bitmap = ((BitmapDrawable) drawableF).getBitmap();
            Intrinsics.checkNotNullExpressionValue(bitmap, "getBitmap(...)");
            if (bitmap != null && (bitmap.getWidth() > i2 || bitmap.getHeight() > i2)) {
                if (bitmap.getHeight() > bitmap.getWidth()) {
                    height = i2;
                    i2 = (int) (bitmap.getWidth() * (i2 / bitmap.getHeight()));
                } else {
                    height = (int) (bitmap.getHeight() * (i2 / bitmap.getWidth()));
                }
                bitmap = Bitmap.createScaledBitmap(bitmap, i2, height, true);
            }
            Intrinsics.checkNotNullExpressionValue(bitmap, "getScaledBitmapAtLongestSide(...)");
        } else {
            if (!(drawableF instanceof androidx.vectordrawable.graphics.drawable.p) && !(drawableF instanceof VectorDrawable)) {
                throw new IllegalArgumentException("Unsupported Drawable Type");
            }
            Bitmap bitmapCreateBitmap = Bitmap.createBitmap(i2, i2, Bitmap.Config.ARGB_8888);
            Intrinsics.checkNotNullExpressionValue(bitmapCreateBitmap, "createBitmap(...)");
            Canvas canvas = new Canvas(bitmapCreateBitmap);
            drawableF.setBounds(0, 0, canvas.getWidth(), canvas.getHeight());
            drawableF.draw(canvas);
            bitmap = bitmapCreateBitmap;
        }
        bitmap.setDensity(160);
        new BitmapDrawable(context.getResources(), bitmap);
    }

    public static byte[] d(String initialHTMLParsed, byte[] initialEditorContentParsedSHA256) {
        Intrinsics.checkNotNullParameter(initialHTMLParsed, "initialHTMLParsed");
        Intrinsics.checkNotNullParameter(initialEditorContentParsedSHA256, "initialEditorContentParsedSHA256");
        try {
            if (initialEditorContentParsedSHA256.length != 0 && !Arrays.equals(initialEditorContentParsedSHA256, f(""))) {
                return initialEditorContentParsedSHA256;
            }
            return f(initialHTMLParsed);
        } catch (Throwable unused) {
            return new byte[0];
        }
    }

    public static byte[] f(String s) throws NoSuchAlgorithmException {
        Intrinsics.checkNotNullParameter(s, "s");
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] bytes = s.getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
        messageDigest.update(bytes);
        byte[] bArrDigest = messageDigest.digest();
        Intrinsics.checkNotNullExpressionValue(bArrDigest, "digest(...)");
        return bArrDigest;
    }

    public static Intent i(b bVar, Context context, long j, int i) {
        bVar.getClass();
        Intent intent = new Intent(context, (Class<?>) ProfileActivity.class);
        intent.putExtra("userId", j);
        intent.putExtra("jumpToTab", i);
        intent.putExtra("badgeId", (String) null);
        return intent;
    }

    @Override // com.quizlet.mapper.a
    public Object a(Object obj) {
        RemoteEntitlementData input = (RemoteEntitlementData) obj;
        Intrinsics.checkNotNullParameter(input, "input");
        RemoteMeteringMeta remoteMeteringMeta = input.c;
        Integer numValueOf = remoteMeteringMeta != null ? Integer.valueOf(remoteMeteringMeta.a) : null;
        RemoteMeteringMeta remoteMeteringMeta2 = input.c;
        return new S(input.a, input.b, new C4185z0(numValueOf, remoteMeteringMeta2 != null ? Integer.valueOf(remoteMeteringMeta2.b) : null));
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        EmailCheckResponse response = (EmailCheckResponse) obj;
        Intrinsics.checkNotNullParameter(response, "response");
        return com.quizlet.quizletandroid.ui.onboarding.a.a(response);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public Object c(Object obj) {
        RemoteIrrelevantRecommendation remote = (RemoteIrrelevantRecommendation) obj;
        Intrinsics.checkNotNullParameter(remote, "remote");
        Long l = remote.a;
        return new C4161r0(remote.b, remote.c, remote.d, l);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        return T.f(this, list);
    }

    public Intent g(Context context, long j) {
        Intrinsics.checkNotNullParameter(context, "context");
        return i(this, context, j, -1);
    }

    @Override // com.quizlet.remote.mapper.base.c
    public Object h(Object obj) {
        C4161r0 data = (C4161r0) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        return new RemoteIrrelevantRecommendation(data.a, data.b, data.c, data.d, null);
    }
}
