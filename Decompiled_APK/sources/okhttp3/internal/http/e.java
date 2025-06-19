package okhttp3.internal.http;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3335e2;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.C5083l;
import okhttp3.H;
import okhttp3.n;
import okhttp3.r;
import okhttp3.s;
import okio.k;

/* loaded from: classes3.dex */
public abstract class e {
    static {
        k kVar = k.d;
        com.quizlet.quizletandroid.ui.common.images.capture.b.i("\"\\");
        com.quizlet.quizletandroid.ui.common.images.capture.b.i("\t ,=");
    }

    public static final boolean a(H h) {
        Intrinsics.checkNotNullParameter(h, "<this>");
        if (Intrinsics.b(h.a.b, "HEAD")) {
            return false;
        }
        int i = h.d;
        return (((i >= 100 && i < 200) || i == 204 || i == 304) && okhttp3.internal.b.l(h) == -1 && !"chunked".equalsIgnoreCase(H.a("Transfer-Encoding", h))) ? false : true;
    }

    public static final void b(n nVar, s url, r headers) {
        List listUnmodifiableList;
        Intrinsics.checkNotNullParameter(nVar, "<this>");
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(headers, "headers");
        if (nVar == n.a) {
            return;
        }
        Pattern pattern = C5083l.j;
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(headers, "headers");
        List listH = headers.h("Set-Cookie");
        int size = listH.size();
        ArrayList arrayList = null;
        for (int i = 0; i < size; i++) {
            C5083l c5083lL = AbstractC3335e2.l(url, (String) listH.get(i));
            if (c5083lL != null) {
                if (arrayList == null) {
                    arrayList = new ArrayList();
                }
                arrayList.add(c5083lL);
            }
        }
        if (arrayList != null) {
            listUnmodifiableList = Collections.unmodifiableList(arrayList);
            Intrinsics.checkNotNullExpressionValue(listUnmodifiableList, "{\n        Collections.un…ableList(cookies)\n      }");
        } else {
            listUnmodifiableList = K.a;
        }
        if (listUnmodifiableList.isEmpty()) {
            return;
        }
        nVar.a(url, listUnmodifiableList);
    }
}
