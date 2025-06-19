package androidx.compose.ui.text.font;

import android.content.Context;
import android.graphics.Paint;
import android.graphics.Typeface;
import com.google.android.gms.internal.mlkit_vision_barcode.K5;
import com.google.android.gms.internal.mlkit_vision_barcode.U5;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.ui.text.font.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0987a {
    public final Context a;

    public C0987a(@NotNull Context context) {
        this.a = context.getApplicationContext();
    }

    public final Typeface a(A a) {
        if (!(a instanceof A)) {
            return null;
        }
        a.getClass();
        int i = a.a;
        Context context = this.a;
        Typeface typefaceA = androidx.core.content.res.k.a(context, i);
        Intrinsics.d(typefaceA);
        t tVar = a.c;
        ThreadLocal threadLocal = C.a;
        if (typefaceA == null) {
            return null;
        }
        ArrayList arrayList = tVar.a;
        if (arrayList.isEmpty()) {
            return typefaceA;
        }
        ThreadLocal threadLocal2 = C.a;
        Paint paint = (Paint) threadLocal2.get();
        if (paint == null) {
            paint = new Paint();
            threadLocal2.set(paint);
        }
        paint.setTypeface(typefaceA);
        paint.setFontVariationSettings(U5.b(arrayList, null, new androidx.compose.ui.draganddrop.d(K5.b(context), 2), 31));
        return paint.getTypeface();
    }
}
