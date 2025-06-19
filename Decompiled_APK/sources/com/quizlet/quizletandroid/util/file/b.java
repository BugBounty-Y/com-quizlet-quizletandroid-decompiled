package com.quizlet.quizletandroid.util.file;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.ImageDecoder;
import android.net.Uri;
import android.os.Build;
import android.provider.MediaStore;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.repository.set.f;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public final /* synthetic */ f j;
    public final /* synthetic */ String k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(f fVar, String str, h hVar) {
        super(2, hVar);
        this.j = fVar;
        this.k = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws IOException {
        Bitmap bitmapDecodeBitmap;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        f fVar = this.j;
        Uri uri = (Uri) ((com.quizlet.quizletandroid.ui.common.images.capture.a) fVar.c).h(this.k);
        Context context = (Context) fVar.b;
        File fileCreateTempFile = File.createTempFile("image", ".jpg", context.getCacheDir());
        Intrinsics.checkNotNullExpressionValue(fileCreateTempFile, "createTempFile(...)");
        if (Build.VERSION.SDK_INT < 28) {
            bitmapDecodeBitmap = MediaStore.Images.Media.getBitmap(context.getContentResolver(), uri);
        } else {
            ImageDecoder.Source sourceCreateSource = ImageDecoder.createSource(context.getContentResolver(), uri);
            Intrinsics.checkNotNullExpressionValue(sourceCreateSource, "createSource(...)");
            bitmapDecodeBitmap = ImageDecoder.decodeBitmap(sourceCreateSource);
        }
        FileOutputStream fileOutputStream = new FileOutputStream(fileCreateTempFile);
        try {
            bitmapDecodeBitmap.compress(Bitmap.CompressFormat.JPEG, 80, fileOutputStream);
            fileOutputStream.close();
            return Uri.fromFile(fileCreateTempFile).toString();
        } finally {
        }
    }
}
