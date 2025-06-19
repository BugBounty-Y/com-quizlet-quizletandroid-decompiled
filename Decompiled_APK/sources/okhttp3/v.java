package okhttp3;

import androidx.transition.C1405h;
import com.quizlet.api.cookie.QuizletCookieManager;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.Pair;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class v implements n {
    public final QuizletCookieManager b;

    public v(QuizletCookieManager cookieHandler) {
        Intrinsics.checkNotNullParameter(cookieHandler, "cookieHandler");
        this.b = cookieHandler;
    }

    @Override // okhttp3.n
    public final void a(s url, List cookies) {
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(cookies, "cookies");
        ArrayList arrayList = new ArrayList();
        Iterator it2 = cookies.iterator();
        while (it2.hasNext()) {
            C5083l cookie = (C5083l) it2.next();
            Intrinsics.checkNotNullParameter(cookie, "cookie");
            arrayList.add(cookie.a(true));
        }
        try {
            this.b.put(url.j(), U.b(new Pair("Set-Cookie", arrayList)));
        } catch (IOException e) {
            okhttp3.internal.platform.o oVar = okhttp3.internal.platform.o.a;
            okhttp3.internal.platform.o oVar2 = okhttp3.internal.platform.o.a;
            StringBuilder sb = new StringBuilder("Saving cookies failed for ");
            s sVarI = url.i("/...");
            Intrinsics.d(sVarI);
            sb.append(sVarI);
            String string = sb.toString();
            oVar2.getClass();
            okhttp3.internal.platform.o.i(5, string, e);
        }
    }

    @Override // okhttp3.n
    public final List b(s url) throws IOException {
        Intrinsics.checkNotNullParameter(url, "url");
        try {
            Map<String, List<String>> cookieHeaders = this.b.get(url.j(), V.c());
            Intrinsics.checkNotNullExpressionValue(cookieHeaders, "cookieHeaders");
            ArrayList arrayList = null;
            for (Map.Entry<String, List<String>> entry : cookieHeaders.entrySet()) {
                String key = entry.getKey();
                List<String> value = entry.getValue();
                if ("Cookie".equalsIgnoreCase(key) || "Cookie2".equalsIgnoreCase(key)) {
                    Intrinsics.checkNotNullExpressionValue(value, "value");
                    if (value.isEmpty()) {
                        continue;
                    } else {
                        for (String header : value) {
                            if (arrayList == null) {
                                arrayList = new ArrayList();
                            }
                            Intrinsics.checkNotNullExpressionValue(header, "header");
                            ArrayList arrayList2 = new ArrayList();
                            int length = header.length();
                            int i = 0;
                            while (i < length) {
                                int iG = okhttp3.internal.b.g(header, i, ";,", length);
                                int iF = okhttp3.internal.b.f(header, '=', i, iG);
                                String name = okhttp3.internal.b.A(i, iF, header);
                                if (!kotlin.text.D.r(name, "$", false)) {
                                    String value2 = iF < iG ? okhttp3.internal.b.A(iF + 1, iG, header) : "";
                                    if (kotlin.text.D.r(value2, "\"", false) && kotlin.text.D.k(value2, "\"", false)) {
                                        value2 = value2.substring(1, value2.length() - 1);
                                        Intrinsics.checkNotNullExpressionValue(value2, "this as java.lang.String…ing(startIndex, endIndex)");
                                    }
                                    Intrinsics.checkNotNullParameter(name, "name");
                                    if (!Intrinsics.b(StringsKt.g0(name).toString(), name)) {
                                        throw new IllegalArgumentException("name is not trimmed");
                                    }
                                    Intrinsics.checkNotNullParameter(value2, "value");
                                    if (!Intrinsics.b(StringsKt.g0(value2).toString(), value2)) {
                                        throw new IllegalArgumentException("value is not trimmed");
                                    }
                                    String domain = url.d;
                                    Intrinsics.checkNotNullParameter(domain, "domain");
                                    String strD = C1405h.d(domain);
                                    if (strD == null) {
                                        throw new IllegalArgumentException("unexpected domain: ".concat(domain));
                                    }
                                    arrayList2.add(new C5083l(name, value2, 253402300799999L, strD, "/", false, false, false, false));
                                }
                                i = iG + 1;
                            }
                            arrayList.addAll(arrayList2);
                        }
                    }
                }
            }
            if (arrayList == null) {
                return kotlin.collections.K.a;
            }
            List listUnmodifiableList = Collections.unmodifiableList(arrayList);
            Intrinsics.checkNotNullExpressionValue(listUnmodifiableList, "{\n      Collections.unmo…fiableList(cookies)\n    }");
            return listUnmodifiableList;
        } catch (IOException e) {
            okhttp3.internal.platform.o oVar = okhttp3.internal.platform.o.a;
            okhttp3.internal.platform.o oVar2 = okhttp3.internal.platform.o.a;
            StringBuilder sb = new StringBuilder("Loading cookies failed for ");
            s sVarI = url.i("/...");
            Intrinsics.d(sVarI);
            sb.append(sVarI);
            String string = sb.toString();
            oVar2.getClass();
            okhttp3.internal.platform.o.i(5, string, e);
            return kotlin.collections.K.a;
        }
    }
}
