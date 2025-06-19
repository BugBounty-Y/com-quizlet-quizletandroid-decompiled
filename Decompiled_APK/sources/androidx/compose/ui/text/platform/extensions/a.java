package androidx.compose.ui.text.platform.extensions;

import android.os.LocaleList;
import android.text.style.LocaleSpan;
import androidx.compose.ui.text.intl.b;
import androidx.compose.ui.text.platform.d;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Locale;
import kotlin.collections.C;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class a {
    public static final a a = new a();

    @NotNull
    public final Object a(@NotNull b bVar) {
        ArrayList arrayList = new ArrayList(C.q(bVar, 10));
        Iterator<E> it2 = bVar.iterator();
        while (it2.hasNext()) {
            arrayList.add(((androidx.compose.ui.text.intl.a) it2.next()).a);
        }
        Locale[] localeArr = (Locale[]) arrayList.toArray(new Locale[0]);
        return new LocaleSpan(new LocaleList((Locale[]) Arrays.copyOf(localeArr, localeArr.length)));
    }

    public final void b(@NotNull d dVar, @NotNull b bVar) {
        ArrayList arrayList = new ArrayList(C.q(bVar, 10));
        Iterator<E> it2 = bVar.iterator();
        while (it2.hasNext()) {
            arrayList.add(((androidx.compose.ui.text.intl.a) it2.next()).a);
        }
        Locale[] localeArr = (Locale[]) arrayList.toArray(new Locale[0]);
        dVar.setTextLocales(new LocaleList((Locale[]) Arrays.copyOf(localeArr, localeArr.length)));
    }
}
