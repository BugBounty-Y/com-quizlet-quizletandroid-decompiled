package io.ktor.client.engine.okhttp;

import androidx.compose.ui.node.B;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3162h7;
import io.ktor.http.k;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeMap;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.N;
import okhttp3.r;

/* loaded from: classes3.dex */
public final class h implements k {
    public final /* synthetic */ r c;

    public h(r rVar) {
        this.c = rVar;
    }

    @Override // io.ktor.util.l
    public final Set a() {
        r rVar = this.c;
        Intrinsics.checkNotNullParameter(N.a, "<this>");
        Comparator CASE_INSENSITIVE_ORDER = String.CASE_INSENSITIVE_ORDER;
        Intrinsics.checkNotNullExpressionValue(CASE_INSENSITIVE_ORDER, "CASE_INSENSITIVE_ORDER");
        TreeMap treeMap = new TreeMap(CASE_INSENSITIVE_ORDER);
        int size = rVar.size();
        for (int i = 0; i < size; i++) {
            String strB = rVar.b(i);
            Locale locale = Locale.US;
            String strK = B.k(locale, "US", strB, locale, "this as java.lang.String).toLowerCase(locale)");
            List arrayList = (List) treeMap.get(strK);
            if (arrayList == null) {
                arrayList = new ArrayList(2);
                treeMap.put(strK, arrayList);
            }
            arrayList.add(rVar.g(i));
        }
        return treeMap.entrySet();
    }

    @Override // io.ktor.util.l
    public final void b(Function2 function2) {
        com.quizlet.features.settings.composables.dialogs.a body = (com.quizlet.features.settings.composables.dialogs.a) function2;
        Intrinsics.checkNotNullParameter(body, "body");
        AbstractC3162h7.c(this, body);
    }

    @Override // io.ktor.util.l
    public final boolean c() {
        return true;
    }

    @Override // io.ktor.util.l
    public final String d(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(name, "name");
        List listH = this.c.h(name);
        if (listH.isEmpty()) {
            listH = null;
        }
        if (listH != null) {
            return (String) CollectionsKt.firstOrNull(listH);
        }
        return null;
    }
}
