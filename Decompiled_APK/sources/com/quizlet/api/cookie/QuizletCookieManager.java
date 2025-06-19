package com.quizlet.api.cookie;

import com.quizlet.infra.contracts.api.a;
import com.quizlet.security.qltj.core.b;
import com.quizlet.security.qltj.core.c;
import java.io.IOException;
import java.net.CookieManager;
import java.net.URI;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlinx.coroutines.E;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class QuizletCookieManager extends CookieManager {

    @NotNull
    private final a qltjReceiver;

    public QuizletCookieManager(a qltjReceiver) {
        Intrinsics.checkNotNullParameter(qltjReceiver, "qltjReceiver");
        this.qltjReceiver = qltjReceiver;
    }

    @Override // java.net.CookieManager, java.net.CookieHandler
    public final void put(URI uri, Map headers) throws IOException {
        Object next;
        Intrinsics.checkNotNullParameter(headers, "headers");
        super.put(uri, headers);
        List cookies = (List) headers.get("Set-Cookie");
        if (cookies != null) {
            c cVar = (c) this.qltjReceiver;
            cVar.getClass();
            Intrinsics.checkNotNullParameter(cookies, "cookies");
            Iterator it2 = cookies.iterator();
            while (true) {
                if (!it2.hasNext()) {
                    next = null;
                    break;
                } else {
                    next = it2.next();
                    if (D.r((String) next, "qltj=", false)) {
                        break;
                    }
                }
            }
            String str = (String) next;
            if ((Intrinsics.b(str != null ? c.a(str) : null, cVar.c) && cVar.d > 1) || uri == null || str == null) {
                return;
            }
            E.A(cVar.b, null, null, new b(str, uri, cVar, null), 3);
        }
    }
}
