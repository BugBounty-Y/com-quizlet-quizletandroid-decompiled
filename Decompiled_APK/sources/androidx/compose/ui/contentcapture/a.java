package androidx.compose.ui.contentcapture;

import android.os.Build;
import android.os.Looper;
import android.util.LongSparseArray;
import android.view.translation.TranslationRequestValue;
import android.view.translation.TranslationResponseValue;
import android.view.translation.ViewTranslationRequest;
import android.view.translation.ViewTranslationResponse;
import androidx.compose.ui.platform.P0;
import androidx.compose.ui.semantics.j;
import androidx.compose.ui.semantics.o;
import androidx.compose.ui.semantics.r;
import androidx.compose.ui.text.C0995g;
import com.google.android.gms.internal.mlkit_vision_barcode.U5;
import java.util.List;
import java.util.function.Consumer;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class a {
    public static final a a = new a();

    public static void a(c cVar, LongSparseArray longSparseArray) {
        TranslationResponseValue value;
        CharSequence text;
        P0 p0;
        o oVar;
        Function1 function1;
        androidx.core.util.b bVar = new androidx.core.util.b(longSparseArray);
        while (bVar.hasNext()) {
            long jA = bVar.a();
            ViewTranslationResponse viewTranslationResponseP = androidx.camera.camera2.internal.compat.quirk.c.p(longSparseArray.get(jA));
            if (viewTranslationResponseP != null && (value = viewTranslationResponseP.getValue("android:text")) != null && (text = value.getText()) != null && (p0 = (P0) cVar.b().e((int) jA)) != null && (oVar = p0.a) != null) {
                Object obj = oVar.d.a.get(j.j);
                if (obj == null) {
                    obj = null;
                }
                androidx.compose.ui.semantics.a aVar = (androidx.compose.ui.semantics.a) obj;
                if (aVar != null && (function1 = (Function1) aVar.b) != null) {
                }
            }
        }
    }

    public final void b(@NotNull c cVar, @NotNull long[] jArr, @NotNull int[] iArr, @NotNull Consumer<ViewTranslationRequest> consumer) {
        o oVar;
        String strB;
        for (long j : jArr) {
            P0 p0 = (P0) cVar.b().e((int) j);
            if (p0 != null && (oVar = p0.a) != null) {
                androidx.camera.camera2.internal.compat.quirk.c.t();
                ViewTranslationRequest.Builder builderN = androidx.camera.camera2.internal.compat.quirk.c.n(cVar.a.getAutofillId(), oVar.g);
                Object obj = oVar.d.a.get(r.u);
                if (obj == null) {
                    obj = null;
                }
                List list = (List) obj;
                if (list != null && (strB = U5.b(list, "\n", null, 62)) != null) {
                    builderN.setValue("android:text", TranslationRequestValue.forText(new C0995g(6, strB, null)));
                    consumer.accept(builderN.build());
                }
            }
        }
    }

    public final void c(@NotNull c cVar, @NotNull LongSparseArray<ViewTranslationResponse> longSparseArray) {
        if (Build.VERSION.SDK_INT < 31) {
            return;
        }
        if (Intrinsics.b(Looper.getMainLooper().getThread(), Thread.currentThread())) {
            a(cVar, longSparseArray);
        } else {
            cVar.a.post(new androidx.activity.r(23, cVar, longSparseArray));
        }
    }
}
