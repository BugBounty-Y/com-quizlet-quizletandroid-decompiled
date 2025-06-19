package org.wordpress.android.util;

import android.util.Log;
import com.quizlet.data.model.AbstractC4178x;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.TimeZone;
import org.jsoup.parser.C;

/* loaded from: classes3.dex */
public abstract class a {
    public static final ArrayList a = new ArrayList(0);

    static {
        TimeZone.getTimeZone("UTC");
        new C(2);
    }

    public static void a() {
        Iterator it2 = new ArrayList(a).iterator();
        if (it2.hasNext()) {
            throw android.support.v4.media.session.a.d(it2);
        }
    }

    public static void b(String str) {
        if (str == null) {
            str = "";
        }
        Log.e("WordPress-".concat(AbstractC4178x.u(2)), str);
        a();
    }

    public static void c(String str) {
        if (str == null) {
            str = "";
        }
        Log.w("WordPress-".concat(AbstractC4178x.u(2)), str);
        a();
    }
}
