package com.google.android.gms.internal.mlkit_vision_camera;

import android.content.Context;
import android.graphics.Bitmap;
import androidx.compose.ui.graphics.C0848h;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;

/* loaded from: classes2.dex */
public abstract class q3 {
    public static final /* synthetic */ int a = 0;

    public static final androidx.compose.ui.graphics.painter.b a(coil3.j jVar, Context context, int i) {
        if (!(jVar instanceof coil3.a)) {
            return jVar instanceof coil3.e ? new com.google.accompanist.drawablepainter.a(coil3.n.b(jVar, context.getResources()).mutate()) : new coil3.compose.q(jVar);
        }
        Bitmap bitmap = ((coil3.a) jVar).a;
        androidx.compose.ui.graphics.painter.a aVar = new androidx.compose.ui.graphics.painter.a(new C0848h(bitmap), R5.a(bitmap.getWidth(), bitmap.getHeight()));
        aVar.h = i;
        return aVar;
    }
}
