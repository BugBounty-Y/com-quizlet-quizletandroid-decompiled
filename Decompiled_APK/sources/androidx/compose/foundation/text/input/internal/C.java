package androidx.compose.foundation.text.input.internal;

import android.os.LocaleList;
import android.view.inputmethod.EditorInfo;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class C {
    public static final C a = new C();

    public final void a(@NotNull EditorInfo editorInfo, @NotNull androidx.compose.ui.text.intl.b bVar) {
        androidx.compose.ui.text.intl.b bVar2 = androidx.compose.ui.text.intl.b.c;
        if (Intrinsics.b(bVar, androidx.compose.ui.text.intl.b.c)) {
            editorInfo.hintLocales = null;
            return;
        }
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(bVar, 10));
        Iterator<E> it2 = bVar.iterator();
        while (it2.hasNext()) {
            arrayList.add(((androidx.compose.ui.text.intl.a) it2.next()).a);
        }
        Locale[] localeArr = (Locale[]) arrayList.toArray(new Locale[0]);
        editorInfo.hintLocales = new LocaleList((Locale[]) Arrays.copyOf(localeArr, localeArr.length));
    }
}
